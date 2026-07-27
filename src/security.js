// Security helpers: escaping, safe redirects, CSRF (synchronizer token),
// audit log helper, password policy.
const crypto = require('crypto');
const prisma = require('./db');

function esc(s = '') {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

// Reject open redirects. Only allow relative paths within the app.
function safeNext(next, fallback = '/') {
  if (typeof next !== 'string') return fallback;
  if (!next.startsWith('/')) return fallback;
  if (next.startsWith('//')) return fallback;              // protocol-relative
  if (next.includes('\\')) return fallback;
  if (next.includes('\n') || next.includes('\r')) return fallback;
  return next;
}

// CSRF: session-bound synchronizer token, embedded in every form,
// checked on every state-changing request.
function csrfField(session) {
  if (!session) return '';
  return `<input type="hidden" name="_csrf" value="${esc(session.csrfToken)}">`;
}

function verifyCsrf(session, submitted) {
  if (!session || !submitted) return false;
  const a = Buffer.from(session.csrfToken || '');
  const b = Buffer.from(String(submitted));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function requireCsrf(req, res, next) {
  if (!verifyCsrf(req.session, req.body?._csrf)) {
    return res.status(403).send('Bad CSRF token');
  }
  next();
}

async function audit({ actorId = null, action, target = null, ip = null, ua = null, meta = null }) {
  try {
    await prisma.auditLog.create({
      data: { actorId, action, target, ip, ua,
              meta: meta ? JSON.stringify(meta) : null },
    });
  } catch (e) {
    console.error('[audit] write failed', e);
  }
}

// Password policy: 12+ chars, must contain 3 of {lower, upper, digit, symbol}.
function passwordProblem(pw) {
  if (typeof pw !== 'string' || pw.length < 12) return 'Password must be at least 12 characters.';
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(r => r.test(pw)).length;
  if (classes < 3) return 'Password must include 3 of: lowercase, uppercase, digit, symbol.';
  return null;
}

function clientIp(req) {
  // trust proxy is enabled in portal.js when behind CF Tunnel; req.ip is the real one then.
  return req.ip;
}

function clientUa(req) {
  return String(req.get('user-agent') || '').slice(0, 200);
}

module.exports = { esc, safeNext, csrfField, verifyCsrf, requireCsrf, audit, passwordProblem, clientIp, clientUa };
