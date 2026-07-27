// AES-256-GCM helpers. Key is 32 bytes hex in env MESSAGE_KEY_HEX.
const crypto = require('crypto');

function getKey() {
  const hex = process.env.MESSAGE_KEY_HEX;
  if (!hex || hex.length !== 64) {
    throw new Error('MESSAGE_KEY_HEX must be 64 hex chars (32 bytes)');
  }
  return Buffer.from(hex, 'hex');
}

// Text encrypt/decrypt (returns hex).
function encrypt(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('hex'), tag: tag.toString('hex'), cipher: ct.toString('hex') };
}

function decrypt({ iv, tag, cipher }) {
  const d = crypto.createDecipheriv('aes-256-gcm', getKey(), Buffer.from(iv, 'hex'));
  d.setAuthTag(Buffer.from(tag, 'hex'));
  const pt = Buffer.concat([d.update(Buffer.from(cipher, 'hex')), d.final()]);
  return pt.toString('utf8');
}

// Buffer encrypt/decrypt for attachments (returns raw buffers).
function encryptBuffer(buf) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
  const ct = Buffer.concat([cipher.update(buf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('hex'), tag: tag.toString('hex'), ciphertext: ct };
}

function decryptBuffer({ iv, tag, ciphertext }) {
  const d = crypto.createDecipheriv('aes-256-gcm', getKey(), Buffer.from(iv, 'hex'));
  d.setAuthTag(Buffer.from(tag, 'hex'));
  return Buffer.concat([d.update(ciphertext), d.final()]);
}

function newToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function newOtp() {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
}

module.exports = { encrypt, decrypt, encryptBuffer, decryptBuffer, newToken, newOtp };
