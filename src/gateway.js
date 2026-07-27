// SMTP submission gateway.
// Accepts mail from local senders (Zoho outbound relay-out, or your MUA/Postfix),
// inspects the subject for TRIGGER_KEYWORD ([secure]), and either:
//   (a) encrypts body + attachments, stores them, and sends a notification with
//       a portal link via Zoho outbound relay, OR
//   (b) forwards the raw message unchanged to Zoho outbound relay.
require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { SMTPServer } = require('smtp-server');
const { simpleParser } = require('mailparser');
const prisma = require('./db');
const { encrypt, encryptBuffer, newToken } = require('./crypto');
const { relayRaw, sendNotification } = require('./mailer');

const TRIGGER = (process.env.TRIGGER_KEYWORD || '[secure]').toLowerCase();
const TTL_HOURS = Number(process.env.MESSAGE_TTL_HOURS || 168);
const PORTAL_URL = process.env.PORTAL_URL || 'http://localhost:3010';
const STORAGE_ROOT = process.env.STORAGE_ROOT || path.join(__dirname, '..', 'storage');
const MAX_ATT_MB = Number(process.env.MAX_ATTACHMENT_MB || 25);
const MAX_TOTAL_MB = Number(process.env.MAX_TOTAL_MB || 40);
const MAX_ATT_BYTES = MAX_ATT_MB * 1024 * 1024;
const MAX_TOTAL_BYTES = MAX_TOTAL_MB * 1024 * 1024;

fs.mkdirSync(STORAGE_ROOT, { recursive: true });

function isSecure(subject = '') {
  return subject.toLowerCase().includes(TRIGGER);
}
function stripTrigger(subject = '') {
  const re = new RegExp(TRIGGER.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'ig');
  return subject.replace(re, '').replace(/\s+/g, ' ').trim();
}

async function handleSecure({ parsed, envelope }) {
  const token = newToken();
  const subjectClean = stripTrigger(parsed.subject || '');
  const recipient = envelope.rcptTo[0].address;
  const senderEmail = envelope.mailFrom.address;

  const atts = parsed.attachments || [];
  const total = atts.reduce((n, a) => n + (a.size || 0), 0);
  if (total > MAX_TOTAL_BYTES) throw new Error(`total attachment size ${total} exceeds ${MAX_TOTAL_BYTES}`);
  for (const a of atts) {
    if ((a.size || 0) > MAX_ATT_BYTES) throw new Error(`attachment ${a.filename} exceeds ${MAX_ATT_BYTES}`);
  }

  const payload = JSON.stringify({ text: parsed.text || '', html: parsed.html || '' });
  const { iv, tag, cipher } = encrypt(payload);

  const expiresAt = new Date(Date.now() + TTL_HOURS * 3600 * 1000);
  const msg = await prisma.message.create({
    data: {
      token, senderEmail, recipientEmail: recipient, subject: subjectClean,
      bodyIv: iv, bodyTag: tag, bodyCipher: cipher,
      headersJson: JSON.stringify({ messageId: parsed.messageId, date: parsed.date }),
      expiresAt,
    },
  });

  const dir = path.join(STORAGE_ROOT, token);
  fs.mkdirSync(dir, { recursive: true });
  for (let i = 0; i < atts.length; i++) {
    const a = atts[i];
    const enc = encryptBuffer(a.content);
    const rel = path.join(token, `${i}.bin`);
    fs.writeFileSync(path.join(STORAGE_ROOT, rel), enc.ciphertext);
    await prisma.attachment.create({
      data: {
        messageId: msg.id,
        idx: i,
        filename: a.filename || `file-${i}`,
        contentType: a.contentType || 'application/octet-stream',
        size: a.size || a.content.length,
        iv: enc.iv,
        tag: enc.tag,
        storagePath: rel,
      },
    });
  }

  await sendNotification({
    to: recipient, senderEmail, subjectClean,
    portalUrl: `${PORTAL_URL}/msg/${token}`,
  });
  console.log(`[gateway] SECURE stored token=${token} to=${recipient} attachments=${atts.length}`);
}

async function handlePassThrough({ envelope, rawBuffer }) {
  await relayRaw({
    envelopeFrom: envelope.mailFrom.address,
    envelopeTo: envelope.rcptTo.map(r => r.address),
    raw: rawBuffer,
  });
  console.log(`[gateway] RELAY to=${envelope.rcptTo.map(r => r.address).join(',')}`);
}

// STARTTLS is enabled when both cert + key env paths point at valid PEM files.
// Auth is optional when GATEWAY_ALLOW_UNAUTH=true (useful when the gateway is
// isolated on a private Docker network behind a trusted MTA).
const tlsCertPath = process.env.STARTTLS_CERT_PATH;
const tlsKeyPath  = process.env.STARTTLS_KEY_PATH;
const tlsEnabled  = Boolean(tlsCertPath && tlsKeyPath && fs.existsSync(tlsCertPath) && fs.existsSync(tlsKeyPath));
const allowUnauth = String(process.env.GATEWAY_ALLOW_UNAUTH || '') === 'true';

const smtpOpts = {
  authOptional: allowUnauth,
  secure: false,
  size: MAX_TOTAL_BYTES + 5 * 1024 * 1024, // leave headroom for envelope + text body
  onAuth(auth, session, cb) {
    if (allowUnauth) return cb(null, { user: auth.username || 'anon' });
    if (auth.username === process.env.GATEWAY_USER &&
        auth.password === process.env.GATEWAY_PASS) return cb(null, { user: auth.username });
    return cb(new Error('Invalid credentials'));
  },
  async onData(stream, session, cb) {
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    const rawBuffer = Buffer.concat(chunks);
    let parsed;
    try { parsed = await simpleParser(rawBuffer); }
    catch (err) { console.error('[gateway] parse error', err); return cb(new Error('Parse failed')); }
    try {
      if (isSecure(parsed.subject || '')) await handleSecure({ parsed, envelope: session.envelope });
      else await handlePassThrough({ envelope: session.envelope, rawBuffer });
      cb();
    } catch (err) {
      console.error('[gateway] handler error', err);
      cb(new Error('Delivery failed: ' + err.message));
    }
  },
};

if (tlsEnabled) {
  smtpOpts.key = fs.readFileSync(tlsKeyPath);
  smtpOpts.cert = fs.readFileSync(tlsCertPath);
  smtpOpts.needsUpgrade = false;
} else {
  smtpOpts.disabledCommands = ['STARTTLS'];
}
const server = new SMTPServer(smtpOpts);

const port = Number(process.env.GATEWAY_PORT || 2525);
const host = process.env.GATEWAY_HOST || '127.0.0.1';
server.listen(port, host, () => {
  console.log(`[gateway] SMTP submission on ${host}:${port} (trigger="${TRIGGER}", max=${MAX_TOTAL_MB}MB)`);
});
