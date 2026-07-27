// Nodemailer transport. Reads SMTP settings from the MailConfig row in the DB
// when present (writable via admin UI); falls back to env vars otherwise.
const nodemailer = require('nodemailer');
const prisma = require('./db');
const { decrypt } = require('./crypto');

let _tx = null;
let _cfg = null;

async function loadDbConfig() {
  try {
    const row = await prisma.mailConfig.findUnique({ where: { id: 'main' } });
    if (row && row.enabled && row.smtpHost && row.smtpPassCt) {
      let pass = '';
      try { pass = decrypt({ iv: row.smtpPassIv, tag: row.smtpPassTag, cipher: row.smtpPassCt }); } catch {}
      return {
        host: row.smtpHost,
        port: row.smtpPort,
        secure: row.smtpSecure,
        user: row.smtpUser,
        pass,
        fromName: row.fromName,
        fromEmail: row.fromEmail,
        source: 'db',
      };
    }
  } catch (e) { /* schema may not have MailConfig yet on first boot */ }
  return null;
}

function loadEnvConfig() {
  return {
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    secure: String(process.env.SMTP_SECURE || 'true') === 'true',
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    fromName: process.env.FROM_NAME || 'Secure',
    fromEmail: process.env.FROM_EMAIL || process.env.SMTP_USER || '',
    source: 'env',
  };
}

async function transport() {
  if (_tx) return _tx;
  const db = await loadDbConfig();
  if (db) {
    _cfg = db;
  } else if (process.env.MAIL_MODE === 'console') {
    _cfg = { source: 'console', fromName: 'Secure', fromEmail: '' };
    _tx = {
      sendMail: async (opts) => {
        console.log('\n[mailer:console] ------ outbound mail ------');
        console.log('to:', opts.to || opts.envelope?.to);
        console.log('from:', opts.from || opts.envelope?.from);
        console.log('subject:', opts.subject);
        if (opts.text) console.log('text:\n' + opts.text);
        if (opts.raw) console.log('raw bytes:', opts.raw.length);
        console.log('---------------------------------------\n');
        return { messageId: 'console-' + Date.now() };
      },
    };
    return _tx;
  } else {
    _cfg = loadEnvConfig();
  }
  const opts = { host: _cfg.host, port: _cfg.port, secure: _cfg.secure };
  if (_cfg.user) opts.auth = { user: _cfg.user, pass: _cfg.pass };
  if (String(process.env.SMTP_IGNORE_TLS || '') === 'true') {
    opts.ignoreTLS = true;
    opts.tls = { rejectUnauthorized: false };
  }
  _tx = nodemailer.createTransport(opts);
  return _tx;
}

function fromHeader() {
  const c = _cfg || loadEnvConfig();
  return `"${c.fromName}" <${c.fromEmail || c.user}>`;
}

function invalidateCache() { _tx = null; _cfg = null; }

// ---------- HTML email templates ----------
function esc(s = '') {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

// Logo served from the portal so mail clients render it inline.
const LOGO_DATA_URI = 'https://secure.Secure.org/logo.png';

const BRAND_BLUE = '#0284c7';
const BRAND_BLUE_DARK = '#0369a1';
const BRAND_INK = '#0f172a';
const BRAND_MUTED = '#64748b';
const BRAND_BORDER = '#e2e8f0';
const BRAND_BG = '#f8fafc';
const BRAND_RED = '#dc2626';

function baseTemplate({ preheader, headingColor, heading, body, cta, footer }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(heading || 'Secure Mail')}</title>
</head>
<body style="margin:0;padding:0;background:${BRAND_BG};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
<span style="display:none;font-size:0;line-height:0;max-height:0;color:transparent;overflow:hidden;">${esc(preheader || '')}</span>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:${BRAND_BG};padding:32px 12px;">
  <tr><td align="center">
    <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#ffffff;border:1px solid ${BRAND_BORDER};border-radius:14px;overflow:hidden;">
      <tr>
        <td style="padding:24px 28px;border-bottom:1px solid ${BRAND_BORDER};">
          <table role="presentation" cellpadding="0" cellspacing="0"><tr>
            <td style="vertical-align:middle;padding-right:10px;"><img src="${LOGO_DATA_URI}" width="32" height="32" alt="" style="display:block;border-radius:6px;"></td>
            <td style="vertical-align:middle;font-weight:600;color:${BRAND_INK};font-size:16px;letter-spacing:-.01em;">Secure Mail</td>
          </tr></table>
        </td>
      </tr>
      <tr>
        <td style="padding:28px;">
          <h1 style="margin:0 0 12px;font-size:20px;font-weight:600;letter-spacing:-.015em;color:${headingColor || BRAND_INK};">${heading}</h1>
          ${body}
          ${cta || ''}
        </td>
      </tr>
      <tr>
        <td style="padding:18px 28px;border-top:1px solid ${BRAND_BORDER};color:${BRAND_MUTED};font-size:12px;line-height:1.5;">
          ${footer || 'Sent by Secure Mail. If this wasn’t expected, you can ignore it.'}
        </td>
      </tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;
}

async function relayRaw({ envelopeFrom, envelopeTo, raw }) {
  return (await transport()).sendMail({
    envelope: { from: envelopeFrom, to: envelopeTo },
    raw,
  });
}

async function sendNotification({ to, senderEmail, subjectClean, portalUrl }) {
  const preheader = `${senderEmail} sent you a secure message.`;
  const body = `
      <p style="margin:0 0 12px;color:${BRAND_INK};font-size:15px;line-height:1.6;">
        <strong>${esc(senderEmail)}</strong> sent you a message that’s only readable in our secure portal.
      </p>
      <p style="margin:0 0 20px;color:${BRAND_INK};font-size:15px;line-height:1.6;">
        Subject: <strong>${esc(subjectClean)}</strong>
      </p>
      <p style="margin:0 0 24px;color:${BRAND_MUTED};font-size:14px;line-height:1.6;">
        The message body stays encrypted until you sign in. You can read it and reply right from the portal.
      </p>`;
  const cta = `
      <table role="presentation" cellpadding="0" cellspacing="0"><tr>
        <td style="border-radius:8px;background:${BRAND_BLUE};">
          <a href="${portalUrl}" style="display:inline-block;padding:12px 20px;color:#ffffff;font-weight:600;text-decoration:none;font-size:14px;letter-spacing:.01em;">Open secure message</a>
        </td>
      </tr></table>
      <p style="margin:16px 0 0;color:${BRAND_MUTED};font-size:12px;word-break:break-all;">Button not working? Paste this into your browser: ${esc(portalUrl)}</p>`;
  const html = baseTemplate({ preheader, heading: 'You have a secure message', body, cta });
  const text =
`${senderEmail} sent you a secure message.

Subject: ${subjectClean}

Open the portal to read it:
${portalUrl}

New here? You can make an account right from that link. Sign-in codes come to your email each time. Don’t forward this link, it’s tied to your session.`;

  return (await transport()).sendMail({
    from: fromHeader(),
    to,
    subject: `You have a secure message from ${senderEmail}`,
    text,
    html,
  });
}

async function sendOtp({ to, code, purpose }) {
  const action = purpose === 'signup' ? 'confirm your email' : 'sign in';
  const accent = purpose === 'admin_login' ? BRAND_RED : BRAND_BLUE;
  const body = `
      <p style="margin:0 0 16px;color:${BRAND_INK};font-size:15px;line-height:1.6;">
        Here’s your one-time code to ${esc(action)}.
      </p>
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%"><tr>
        <td align="center" style="padding:16px 0;">
          <div style="display:inline-block;padding:14px 24px;border-radius:10px;background:#f1f5f9;border:1px solid ${BRAND_BORDER};font-family:'SF Mono','Roboto Mono',Menlo,Consolas,monospace;font-size:28px;letter-spacing:.35em;color:${BRAND_INK};font-weight:600;">
            ${esc(code)}
          </div>
        </td>
      </tr></table>
      <p style="margin:16px 0 0;color:${BRAND_MUTED};font-size:13px;line-height:1.6;">
        Good for ${process.env.OTP_TTL_MINUTES || 10} minutes. If you didn’t just try to sign in, you can ignore this.
      </p>`;
  const html = baseTemplate({
    preheader: `Your one-time code: ${code}`,
    heading: 'Verification code',
    headingColor: accent,
    body,
  });
  const text =
`Your one-time code to ${action}:

    ${code}

Good for ${process.env.OTP_TTL_MINUTES || 10} minutes. If you didn’t just try to sign in, ignore this.`;

  return (await transport()).sendMail({
    from: fromHeader(),
    to,
    subject: `Your secure portal code: ${code}`,
    text,
    html,
  });
}

async function sendReplyBack({ to, replyFrom, subjectClean, portalUrl }) {
  const preheader = `${replyFrom} replied to your secure message.`;
  const body = `
      <p style="margin:0 0 12px;color:${BRAND_INK};font-size:15px;line-height:1.6;">
        <strong>${esc(replyFrom)}</strong> replied through the portal.
      </p>
      <p style="margin:0 0 24px;color:${BRAND_MUTED};font-size:14px;line-height:1.6;">
        Subject: <strong>${esc(subjectClean)}</strong>
      </p>`;
  const cta = `
      <table role="presentation" cellpadding="0" cellspacing="0"><tr>
        <td style="border-radius:8px;background:${BRAND_BLUE};">
          <a href="${portalUrl}" style="display:inline-block;padding:12px 20px;color:#ffffff;font-weight:600;text-decoration:none;font-size:14px;">Open reply</a>
        </td>
      </tr></table>`;
  const html = baseTemplate({ preheader, heading: 'New reply to your secure message', body, cta });
  const text = `${replyFrom} replied.\nSubject: ${subjectClean}\nRead it here: ${portalUrl}`;
  return (await transport()).sendMail({
    from: fromHeader(),
    to,
    subject: `Re: ${subjectClean}`,
    text,
    html,
  });
}

module.exports = { relayRaw, sendNotification, sendOtp, sendReplyBack, fromHeader, invalidateCache };
