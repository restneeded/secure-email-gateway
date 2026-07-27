// Portal web app (recipient-facing) + admin panel.
// Auth: password + email OTP on every login. Sessions are opaque, sliding-window,
// bound to IP+UA. CSRF on every POST. Rate-limited login/OTP/signup.
require('dotenv').config();

const fs = require('fs');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const argon2 = require('argon2');
const sanitizeHtml = require('sanitize-html');

// Strict allowlist for encrypted-message HTML rendering
const SANITIZE_OPTS = {
  allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']),
  allowedAttributes: {
    a: ['href', 'name', 'target', 'rel'],
    img: ['src', 'alt', 'width', 'height'],
    '*': ['style'],
  },
  allowedSchemes: ['http', 'https', 'mailto', 'cid', 'data'],
  allowedSchemesByTag: { img: ['http', 'https', 'data', 'cid'] },
  allowedStyles: {
    '*': {
      color: [/^#(0x)?[0-9a-f]+$/i, /^rgb\(/, /^[a-z]+$/i],
      'background-color': [/^#(0x)?[0-9a-f]+$/i, /^rgb\(/, /^[a-z]+$/i],
      'text-align': [/^left$|^right$|^center$|^justify$/],
      'font-weight': [/^\d+$|^bold$|^normal$/],
      'font-style': [/^italic$|^normal$/],
      'text-decoration': [/^underline$|^line-through$|^none$/],
      'font-size': [/^\d+(\.\d+)?(px|em|rem|%)?$/],
    },
  },
  transformTags: {
    'a': (tagName, attribs) => ({
      tagName: 'a',
      attribs: { ...attribs, target: '_blank', rel: 'noopener noreferrer nofollow' },
    }),
  },
  disallowedTagsMode: 'discard',
};
const prisma = require('./db');
const { decrypt, decryptBuffer, newToken, newOtp } = require('./crypto');
const { sendOtp } = require('./mailer');
const {
  esc, safeNext, csrfField, requireCsrf, audit, passwordProblem, clientIp, clientUa,
} = require('./security');
const adminRouter = require('./admin');

const app = express();

const IS_PROD = process.env.NODE_ENV === 'production';
if (IS_PROD) app.set('trust proxy', 1); // behind Cloudflare Tunnel / Nginx

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // small inline stylesheet only
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      baseUri: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  strictTransportSecurity: IS_PROD ? { maxAge: 63072000, includeSubDomains: true, preload: true } : false,
  referrerPolicy: { policy: 'no-referrer' },
}));

app.use(express.urlencoded({ extended: false, limit: '32kb' }));
app.use(cookieParser());

// Serve the Secure logo
const logoPath = path.join(__dirname, '..', 'public', 'logo.png');
app.get('/logo.png', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.sendFile(logoPath);
});


// Never let a proxy or the browser cache authenticated pages.
app.use((req, res, next) => {
  const p = req.path;
  if (p.startsWith('/static.css')) return next();
  res.setHeader('Cache-Control', 'no-store, private');
  res.setHeader('Pragma', 'no-cache');
  next();
});

const OTP_TTL_MIN = Number(process.env.OTP_TTL_MINUTES || 10);
const SESSION_TTL_MIN = Number(process.env.SESSION_TTL_MINUTES || 30);
const MAX_OTP_ATTEMPTS = 5;
const MAX_LOGIN_FAILS = 5;
const LOCK_MINUTES = 15;
const COOKIE_NAME = IS_PROD ? '__Host-sid' : 'sid';

// ------------- rate limiters -------------
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false });
const otpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false });
const signupLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });

// ------------- layout / helpers -------------
const LOCK_SVG = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
// base64-encoded SVG so the < and > can't confuse the HTML parser inside the href
const FAVICON = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGY0NmU1IiBzdHJva2Utd2lkdGg9IjIuNSIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cmVjdCB4PSIzIiB5PSIxMSIgd2lkdGg9IjE4IiBoZWlnaHQ9IjExIiByeD0iMiIvPjxwYXRoIGQ9Ik03IDExVjdhNSA1IDAgMCAxIDEwIDB2NCIvPjwvc3ZnPg==';
// bumped on every CSS change; used as ?v= to bypass CF edge cache
const CSS_VERSION = 2;

function layout(title, body, opts = {}) {
  const shell = opts.shell || 'app';   // 'auth' = centered card, 'app' = full-width with nav
  const nav = opts.user
    ? `<header class="topbar">
         <div class="brand"><img src="/logo.png" alt="" width="26" height="26" style="border-radius:4px;"><span>Secure Mail</span></div>
         <nav class="topbar-nav">
           <a href="/inbox">Inbox</a>
           ${opts.user.role === 'admin' ? '<a href="/admin">Admin</a>' : ''}
         </nav>
         <div class="topbar-user">
           <span class="user-email">${esc(opts.user.email)}</span>
           ${opts.user.role === 'admin' ? '<span class="chip chip-accent">admin</span>' : ''}
           <form method="post" action="/logout" class="inline">
             ${csrfField(opts.session)}
             <button type="submit" class="btn btn-ghost btn-sm">Sign out</button>
           </form>
         </div>
       </header>`
    : '';
  const wrapOpen  = shell === 'auth' ? '<div class="auth-wrap"><main class="auth-card">' : '<main class="app-main">';
  const wrapClose = shell === 'auth' ? '</main></div>' : '</main>';
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0284c7">
<title>${esc(title)} · Secure Mail</title>
<link rel="icon" href="/logo.png">
<link rel="stylesheet" href="/static.css?v=${CSS_VERSION}">
</head><body class="shell-${shell}">${nav}${wrapOpen}${body}${wrapClose}</body></html>`;
}

app.get('/static.css', (_req, res) => {
  // Short cache so CSS changes propagate within a minute; the ?v= in the URL is
  // the primary cache-buster.
  res.setHeader('Cache-Control', 'public, max-age=60');
  res.type('text/css').send(`
:root {
  color-scheme: light dark;
  --bg: #f7f8fa;
  --surface: #ffffff;
  --surface-alt: #f2f3f7;
  --border: #e4e6eb;
  --border-strong: #d0d3da;
  --text: #0f172a;
  --text-muted: #64748b;
  --text-faint: #94a3b8;
  --primary: #0284c7;
  --primary-hover: #0369a1;
  --primary-soft: #e0f2fe;
  --accent: #dc2626;
  --success: #059669;
  --success-soft: #ecfdf5;
  --danger: #dc2626;
  --danger-soft: #fef2f2;
  --warning: #b45309;
  --warning-soft: #fffbeb;
  --shadow-sm: 0 1px 2px rgba(15,23,42,.04), 0 1px 3px rgba(15,23,42,.06);
  --shadow-md: 0 4px 6px -1px rgba(15,23,42,.06), 0 2px 4px -2px rgba(15,23,42,.06);
  --shadow-lg: 0 20px 40px -12px rgba(15,23,42,.15), 0 8px 16px -8px rgba(15,23,42,.08);
  --radius: 10px;
  --radius-sm: 6px;
  --radius-lg: 16px;
  --font-sans: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", "Inter", Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Monaco, Consolas, "Liberation Mono", monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0a0b0f;
    --surface: #14161c;
    --surface-alt: #1c1e26;
    --border: #262a36;
    --border-strong: #363b4a;
    --text: #f1f5f9;
    --text-muted: #94a3b8;
    --text-faint: #64748b;
    --primary: #38bdf8;
    --primary-hover: #7dd3fc;
    --primary-soft: #082f49;
    --accent: #f87171;
    --success: #34d399;
    --success-soft: #052e2b;
    --danger: #f87171;
    --danger-soft: #3a1414;
    --warning: #fbbf24;
    --warning-soft: #3a2712;
  }
}

* { box-sizing: border-box; }
html, body { height: 100%; }
body {
  margin: 0;
  font-family: var(--font-sans);
  font-size: 15px;
  line-height: 1.6;
  color: var(--text);
  background: var(--bg);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

a { color: var(--primary); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ---------- Auth shell (login / signup / OTP) ---------- */
.auth-wrap {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 2rem 1rem;
  background:
    radial-gradient(1200px 600px at 10% -10%, rgba(99,102,241,.10), transparent 60%),
    radial-gradient(900px 500px at 110% 110%, rgba(79,70,229,.08), transparent 55%),
    var(--bg);
}
.auth-card {
  width: 100%;
  max-width: 420px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
  padding: 2.25rem 2rem;
}
.auth-brand {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: .55rem;
  color: var(--primary);
  font-weight: 600;
  letter-spacing: -.01em;
  margin: 0 0 1.4rem;
}
.auth-brand svg { display: block; }
.auth-title { font-size: 1.35rem; font-weight: 600; letter-spacing: -.015em; margin: 0 0 .35rem; }
.auth-sub { color: var(--text-muted); font-size: .92rem; margin: 0 0 1.5rem; }
.auth-footnote { margin-top: 1.25rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-muted); font-size: .82rem; text-align: center; }

/* ---------- App shell ---------- */
.topbar {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  padding: .75rem 1.25rem;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  position: sticky; top: 0; z-index: 10;
}
.brand {
  display: inline-flex;
  align-items: center;
  gap: .5rem;
  color: var(--primary);
  font-weight: 600;
  letter-spacing: -.01em;
}
.topbar-nav { display: flex; gap: 1rem; flex: 1; }
.topbar-nav a { color: var(--text-muted); font-size: .9rem; font-weight: 500; padding: .25rem 0; }
.topbar-nav a:hover { color: var(--text); text-decoration: none; }
.topbar-user { display: flex; align-items: center; gap: .75rem; font-size: .88rem; color: var(--text-muted); }
.user-email { color: var(--text); font-weight: 500; }
.app-main { max-width: 960px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }

/* ---------- Forms ---------- */
form { display: grid; gap: 1rem; }
form.inline { display: inline; }
label { display: grid; gap: .35rem; font-size: .82rem; color: var(--text-muted); font-weight: 500; }
input[type=email], input[type=password], input[type=text], input[type=search], input[type=number], select, textarea {
  font: inherit;
  color: var(--text);
  background: var(--surface);
  padding: .7rem .85rem;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-strong);
  transition: border-color .15s, box-shadow .15s;
  width: 100%;
}
input:focus, select:focus, textarea:focus {
  outline: none;
  border-color: var(--primary);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--primary) 20%, transparent);
}
input[readonly] { background: var(--surface-alt); color: var(--text-muted); }
.field-hint { font-size: .78rem; color: var(--text-faint); margin: -.35rem 0 0; }
.otp-input {
  text-align: center;
  font-family: var(--font-mono);
  font-size: 1.75rem;
  letter-spacing: .5em;
  padding-left: 1em;
}

/* ---------- Buttons ---------- */
.btn, button {
  font: inherit;
  font-weight: 500;
  padding: .7rem 1.1rem;
  border-radius: var(--radius-sm);
  border: 1px solid transparent;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: .4rem;
  transition: background .15s, border-color .15s, color .15s, transform .05s;
  background: var(--primary);
  color: #fff;
}
.btn:hover, button:hover { background: var(--primary-hover); }
.btn:active, button:active { transform: translateY(1px); }
.btn-secondary, button.secondary {
  background: var(--surface);
  color: var(--text);
  border-color: var(--border-strong);
}
.btn-secondary:hover, button.secondary:hover { background: var(--surface-alt); }
.btn-ghost { background: transparent; color: var(--text-muted); border-color: transparent; padding: .4rem .65rem; }
.btn-ghost:hover { background: var(--surface-alt); color: var(--text); }
.btn-danger { background: var(--danger); }
.btn-danger:hover { background: #b91c1c; }
.btn-sm { padding: .35rem .7rem; font-size: .82rem; }
.btn-block { width: 100%; }
.btn:disabled { opacity: .5; cursor: not-allowed; }

/* ---------- Chips / badges ---------- */
.chip { display: inline-flex; align-items: center; padding: .12rem .5rem; border-radius: 999px; font-size: .72rem; font-weight: 500; background: var(--surface-alt); color: var(--text-muted); border: 1px solid var(--border); }
.chip-accent { background: var(--primary-soft); color: var(--primary); border-color: transparent; }
.chip-success { background: var(--success-soft); color: var(--success); border-color: transparent; }
.chip-danger  { background: var(--danger-soft);  color: var(--danger);  border-color: transparent; }
.chip-warning { background: var(--warning-soft); color: var(--warning); border-color: transparent; }

/* ---------- Alerts ---------- */
.alert { padding: .75rem 1rem; border-radius: var(--radius-sm); font-size: .9rem; margin: 0 0 1rem; border: 1px solid var(--border); background: var(--surface-alt); }
.alert-danger  { background: var(--danger-soft);  color: var(--danger);  border-color: transparent; }
.alert-success { background: var(--success-soft); color: var(--success); border-color: transparent; }
.alert-info    { background: var(--primary-soft); color: var(--primary); border-color: transparent; }

/* ---------- Page header ---------- */
.page-head { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; margin: 0 0 1.5rem; }
.page-head h1 { margin: 0; font-size: 1.5rem; font-weight: 600; letter-spacing: -.02em; }
.page-head .subtle { color: var(--text-muted); font-size: .9rem; }

/* ---------- Card ---------- */
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.25rem 1.5rem;
  box-shadow: var(--shadow-sm);
}
.card + .card { margin-top: 1rem; }
.card-head { display: flex; align-items: center; justify-content: space-between; margin: 0 0 .5rem; }
.card-title { font-weight: 600; font-size: 1rem; margin: 0; }

/* ---------- Message view ---------- */
.msg-meta { display: flex; align-items: center; gap: .75rem; color: var(--text-muted); font-size: .85rem; margin: 0 0 1rem; }
.avatar {
  width: 32px; height: 32px; border-radius: 50%;
  background: var(--primary-soft); color: var(--primary);
  display: inline-flex; align-items: center; justify-content: center;
  font-weight: 600; font-size: .82rem; flex-shrink: 0;
}
.msg-body {
  background: var(--surface-alt);
  border-radius: var(--radius);
  padding: 1.25rem 1.5rem;
  border: 1px solid var(--border);
}
.msg-body pre {
  margin: 0;
  font-family: var(--font-sans);
  font-size: .95rem;
  line-height: 1.7;
  white-space: pre-wrap;
  color: var(--text);
}

/* Rendered HTML from encrypted messages */
.msg-html { color: var(--text); font-size: 15px; line-height: 1.65; }
.msg-html p { margin: 0 0 .75em; }
.msg-html h1, .msg-html h2, .msg-html h3, .msg-html h4 { margin: 1em 0 .5em; letter-spacing: -.01em; color: var(--text); }
.msg-html h1 { font-size: 1.35rem; } .msg-html h2 { font-size: 1.15rem; } .msg-html h3 { font-size: 1rem; }
.msg-html a { color: var(--primary); text-decoration: underline; }
.msg-html ul, .msg-html ol { margin: 0 0 .75em; padding-left: 1.4em; }
.msg-html li { margin: .25em 0; }
.msg-html blockquote { margin: .75em 0; padding: .5em 1em; border-left: 3px solid var(--border-strong); color: var(--text-muted); background: var(--surface-alt); border-radius: 4px; }
.msg-html img { max-width: 100%; height: auto; border-radius: 6px; }
.msg-html table { border-collapse: collapse; margin: .75em 0; font-size: .95rem; }
.msg-html th, .msg-html td { border: 1px solid var(--border); padding: .5em .75em; text-align: left; }
.msg-html code { background: var(--surface-alt); padding: 1px 5px; border-radius: 4px; font-family: var(--font-mono); font-size: .9em; }
.msg-html pre { background: var(--surface-alt); padding: 1em; border-radius: 8px; overflow-x: auto; font-family: var(--font-mono); font-size: .85em; margin: .5em 0; }

.attachments { display: grid; gap: .5rem; margin-top: 1rem; }
.att-item {
  display: flex; align-items: center; gap: .75rem;
  padding: .75rem 1rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  transition: border-color .15s, background .15s;
}
.att-item:hover { border-color: var(--primary); background: var(--primary-soft); text-decoration: none; }
.att-icon { color: var(--text-muted); flex-shrink: 0; }
.att-meta { display: flex; flex-direction: column; }
.att-name { color: var(--text); font-weight: 500; font-size: .92rem; }
.att-detail { color: var(--text-faint); font-size: .78rem; }

/* ---------- Tables ---------- */
table { width: 100%; border-collapse: collapse; font-size: .9rem; }
th, td { text-align: left; padding: .75rem .5rem; border-bottom: 1px solid var(--border); }
th { color: var(--text-muted); font-weight: 500; font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; }
tbody tr:hover { background: var(--surface-alt); }
tbody tr a { color: var(--text); font-weight: 500; }
tbody tr a:hover { color: var(--primary); }
.actions { display: flex; gap: .35rem; flex-wrap: wrap; }
.actions form { display: inline; }
.actions .btn-sm { padding: .3rem .6rem; font-size: .78rem; }

/* ---------- Empty state ---------- */
.empty {
  text-align: center;
  padding: 3rem 1rem;
  color: var(--text-muted);
}
.empty svg { color: var(--text-faint); margin: 0 auto .75rem; display: block; }
.empty h2 { font-size: 1.1rem; color: var(--text); margin: 0 0 .35rem; font-weight: 600; }
.empty p { margin: 0; font-size: .9rem; }

/* ---------- Admin nav ---------- */
.admin-nav {
  display: flex;
  gap: .25rem;
  background: var(--surface);
  border: 1px solid var(--border);
  padding: .35rem;
  border-radius: var(--radius);
  margin: 0 0 1.5rem;
}
.admin-nav a {
  color: var(--text-muted);
  padding: .5rem .9rem;
  border-radius: var(--radius-sm);
  font-size: .88rem;
  font-weight: 500;
}
.admin-nav a:hover { background: var(--surface-alt); color: var(--text); text-decoration: none; }
.admin-nav a.active { background: var(--primary-soft); color: var(--primary); }

/* ---------- Metric cards ---------- */
.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin: 0 0 2rem; }
.metric { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1rem 1.25rem; }
.metric-label { color: var(--text-muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; margin: 0 0 .35rem; font-weight: 500; }
.metric-value { font-size: 1.75rem; font-weight: 600; letter-spacing: -.02em; color: var(--text); }

/* ---------- Utility ---------- */
.mono { font-family: var(--font-mono); font-size: .85rem; }
.muted { color: var(--text-muted); }
.faint { color: var(--text-faint); }
.small { font-size: .82rem; }
.stack { display: grid; gap: 1rem; }
`);
});

// ------------- session middleware -------------
async function loadSession(req, _res, next) {
  const sid = req.cookies[COOKIE_NAME];
  if (!sid) return next();
  const s = await prisma.session.findUnique({ where: { id: sid }, include: { user: true } });
  if (!s || s.expiresAt < new Date() || s.user.disabled) return next();
  // Bind to IP + UA (soft bind for dev; use behind CF Tunnel in prod).
  const ip = clientIp(req);
  const ua = clientUa(req);
  if (IS_PROD && (s.ip !== ip || s.ua !== ua)) {
    await prisma.session.delete({ where: { id: sid } }).catch(() => {});
    return next();
  }
  // Slide expiry.
  const newExp = new Date(Date.now() + SESSION_TTL_MIN * 60 * 1000);
  await prisma.session.update({ where: { id: sid }, data: { lastSeenAt: new Date(), expiresAt: newExp } });
  req.session = s;
  req.user = s.user;
  next();
}
app.use(loadSession);

function setSessionCookie(res, sid) {
  res.cookie(COOKIE_NAME, sid, {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD,
    path: '/',
    maxAge: SESSION_TTL_MIN * 60 * 1000,
  });
}

async function createSession(res, user, req) {
  const sid = newToken(24);
  const csrfToken = newToken(24);
  const expiresAt = new Date(Date.now() + SESSION_TTL_MIN * 60 * 1000);
  const session = await prisma.session.create({
    data: {
      id: sid, userId: user.id, csrfToken,
      ip: clientIp(req), ua: clientUa(req), expiresAt,
    },
  });
  setSessionCookie(res, sid);
  // Mutate req so anything rendered in the same response (e.g. otpForm's CSRF field)
  // has a valid session/user without another cookie round-trip.
  req.session = session;
  req.user = user;
  return session;
}

function requireUser(req, res, next) {
  if (req.user) return next();
  return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
}

async function issueOtp(user, purpose) {
  const code = newOtp();
  const codeHash = await argon2.hash(code, { type: argon2.argon2id });
  const expiresAt = new Date(Date.now() + OTP_TTL_MIN * 60 * 1000);
  await prisma.otpToken.create({ data: { userId: user.id, codeHash, purpose, expiresAt } });
  await sendOtp({ to: user.email, code, purpose });
}

// ------------- entry -------------
app.get('/', (req, res) => res.redirect(req.user ? '/inbox' : '/login'));

app.get('/inbox', requireUser, async (req, res) => {
  const msgs = await prisma.message.findMany({
    where: {
      recipientEmail: req.user.email.toLowerCase(),
      revokedAt: null,
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: 'desc' },
    take: 50,
  });

  const initials = e => (e.split('@')[0].slice(0, 2)).toUpperCase();
  const body = msgs.length
    ? `<div class="card"><table>
         <thead><tr><th>From</th><th>Subject</th><th>Received</th><th>Opens</th></tr></thead>
         <tbody>${msgs.map(m => `<tr>
           <td><span class="avatar" style="margin-right:.5rem;vertical-align:middle;">${esc(initials(m.senderEmail))}</span><span>${esc(m.senderEmail)}</span></td>
           <td><a href="/view/${esc(m.token)}">${esc(m.subject || '(no subject)')}</a></td>
           <td class="muted small">${esc(m.createdAt.toISOString().slice(0,16).replace('T',' '))}</td>
           <td>${m.openCount === 0 ? '<span class="chip">unread</span>' : `<span class="chip chip-success">${m.openCount}</span>`}</td>
         </tr>`).join('')}</tbody></table></div>`
    : `<div class="card empty">
         <svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
         <h2>No secure messages</h2>
         <p>When someone sends you a secure message it’ll show up here.</p>
       </div>`;

  res.send(layout('Inbox', `
    <div class="page-head">
      <h1>Inbox</h1>
      <span class="subtle">${msgs.length} message${msgs.length === 1 ? '' : 's'}</span>
    </div>
    ${body}`,
    { user: req.user, session: req.session }));
});

// Recipient clicks the link in their email.
app.get('/msg/:token', async (req, res) => {
  const msg = await prisma.message.findUnique({ where: { token: req.params.token } });
  if (!msg || msg.revokedAt)
    return res.status(404).send(layout('Not found', '<h1>Message not found</h1>'));
  if (msg.expiresAt < new Date())
    return res.status(410).send(layout('Expired', '<h1>This message has expired.</h1>'));

  const next = `/view/${msg.token}`;
  if (req.user && req.user.email.toLowerCase() === msg.recipientEmail.toLowerCase())
    return res.redirect(next);

  const existing = await prisma.user.findUnique({ where: { email: msg.recipientEmail.toLowerCase() } });
  if (existing) return res.redirect('/login?email=' + encodeURIComponent(msg.recipientEmail) + '&next=' + encodeURIComponent(next));
  return res.redirect('/signup?email=' + encodeURIComponent(msg.recipientEmail) + '&next=' + encodeURIComponent(next));
});

// ------------- signup -------------
app.get('/signup', (req, res) => {
  const email = req.query.email || '';
  const next = safeNext(req.query.next);
  res.send(layout('Create account', `
    <div class="auth-brand"><img src="/logo.png" alt="" width="26" height="26" style="border-radius:4px;"><span>Secure Mail</span></div>
    <h1 class="auth-title">Create your account</h1>
    <p class="auth-sub">Someone sent you a secure message. Set up your account to open it. We’ll email a one-time code to confirm.</p>
    <form method="post" action="/signup">
      <input type="hidden" name="next" value="${esc(next)}">
      <label>Email address
        <input name="email" type="email" required value="${esc(email)}" ${email ? 'readonly' : ''} autocomplete="email">
      </label>
      <label>Password
        <input name="password" type="password" minlength="12" required autocomplete="new-password" placeholder="At least 12 characters">
      </label>
      <p class="field-hint">At least 12 characters, with a mix of lowercase, uppercase, digits, and symbols.</p>
      <button type="submit" class="btn-block">Create account</button>
    </form>
    <p class="auth-footnote">Already have an account? <a href="/login${email ? '?email=' + encodeURIComponent(email) : ''}">Sign in</a></p>`,
    { shell: 'auth' }));
});

app.post('/signup', signupLimiter, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const next = safeNext(req.body.next);
  const authErr = (msg) => layout('Sign up', `
    <div class="auth-brand"><img src="/logo.png" alt="" width="26" height="26" style="border-radius:4px;"><span>Secure Mail</span></div>
    <div class="alert alert-danger">${esc(msg)}</div>
    <p class="auth-footnote"><a href="/signup${email ? '?email=' + encodeURIComponent(email) : ''}">Try again</a></p>`,
    { shell: 'auth' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).send(authErr('Enter a valid email address.'));
  const pwErr = passwordProblem(password);
  if (pwErr) return res.status(400).send(authErr(pwErr));

  let user = await prisma.user.findUnique({ where: { email } });
  if (user) return res.redirect('/login?email=' + encodeURIComponent(email) + '&next=' + encodeURIComponent(next));

  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
  user = await prisma.user.create({ data: { email, passwordHash } });
  await issueOtp(user, 'signup');
  await audit({ actorId: user.id, action: 'user.signup', ip: clientIp(req), ua: clientUa(req) });

  // Create a pre-session solely to carry a CSRF token through OTP.
  await createSession(res, user, req);
  res.send(otpForm({ req, email, next, purpose: 'signup' }));
});

// ------------- login -------------
app.get('/login', (req, res) => {
  const email = req.query.email || '';
  const next = safeNext(req.query.next);
  res.send(layout('Sign in', `
    <div class="auth-brand"><img src="/logo.png" alt="" width="26" height="26" style="border-radius:4px;"><span>Secure Mail</span></div>
    <h1 class="auth-title">Welcome back</h1>
    <p class="auth-sub">Sign in to read your secure messages. After your password we’ll email you a one-time code.</p>
    <form method="post" action="/login">
      <input type="hidden" name="next" value="${esc(next)}">
      <label>Email address
        <input name="email" type="email" required value="${esc(email)}" autocomplete="email" autofocus>
      </label>
      <label>Password
        <input name="password" type="password" required autocomplete="current-password">
      </label>
      <button type="submit" class="btn-block">Continue</button>
    </form>
    <p class="auth-footnote">New here? <a href="/signup${email ? '?email=' + encodeURIComponent(email) : ''}">Create an account</a></p>`,
    { shell: 'auth' }));
});

const bad = () => layout('Sign in', `
    <div class="auth-brand"><img src="/logo.png" alt="" width="26" height="26" style="border-radius:4px;"><span>Secure Mail</span></div>
    <div class="alert alert-danger">Invalid email or password.</div>
    <p class="auth-footnote"><a href="/login">Try again</a></p>`,
    { shell: 'auth' });

app.post('/login', loginLimiter, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const next = safeNext(req.body.next);
  const user = await prisma.user.findUnique({ where: { email } });

  // Constant-ish path: always run argon2.verify to avoid user-enumeration timing.
  const dummy = '$argon2id$v=19$m=65536,t=3,p=4$YWFhYWFhYWFhYWFhYWFhYQ$AAAAAAAAAAAAAAAAAAAAAA';
  const hash = user?.passwordHash || dummy;
  const ok = await argon2.verify(hash, password).catch(() => false);

  // Admins must use the dedicated /admin/login page; refuse them here without
  // leaking that the account exists (same response as a bad credential).
  if (user && user.role === 'admin') {
    await audit({ actorId: user.id, action: 'login.refused.admin_on_user_route', ip: clientIp(req), ua: clientUa(req) });
    return res.status(401).send(bad());
  }
  if (!user || !ok || user.disabled) {
    if (user) {
      const fails = user.failedLoginCount + 1;
      const lock = fails >= MAX_LOGIN_FAILS ? new Date(Date.now() + LOCK_MINUTES * 60 * 1000) : null;
      await prisma.user.update({ where: { id: user.id }, data: { failedLoginCount: fails, lockedUntil: lock } });
      await audit({ actorId: user.id, action: 'login.fail', ip: clientIp(req), ua: clientUa(req) });
    }
    return res.status(401).send(bad());
  }
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    return res.status(423).send(layout('Locked', `
      <div class="auth-brand"><img src="/logo.png" alt="" width="26" height="26" style="border-radius:4px;"><span>Secure Mail</span></div>
      <div class="alert alert-danger">Too many tries. Give it a few minutes and come back.</div>`,
      { shell: 'auth' }));
  }

  await prisma.user.update({ where: { id: user.id }, data: { failedLoginCount: 0, lockedUntil: null } });
  await issueOtp(user, 'login');
  await audit({ actorId: user.id, action: 'login.password.ok', ip: clientIp(req), ua: clientUa(req) });

  // Pre-session so the OTP form can carry a CSRF token.
  await createSession(res, user, req);
  res.send(otpForm({ req, email, next, purpose: 'login' }));
});

function otpForm({ req, email, next, purpose }) {
  const csrf = req.session ? csrfField(req.session) : '';
  return layout('Enter code', `
    <div class="auth-brand"><img src="/logo.png" alt="" width="26" height="26" style="border-radius:4px;"><span>Secure Mail</span></div>
    <h1 class="auth-title">Check your email</h1>
    <p class="auth-sub">We sent a 6-digit code to <b>${esc(email)}</b>. Good for ${OTP_TTL_MIN} minutes.</p>
    <form method="post" action="/otp">
      ${csrf}
      <input type="hidden" name="next" value="${esc(next)}">
      <input type="hidden" name="email" value="${esc(email)}">
      <input type="hidden" name="purpose" value="${esc(purpose)}">
      <label>Verification code
        <input name="code" class="otp-input" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autofocus autocomplete="one-time-code" placeholder="000000">
      </label>
      <button type="submit" class="btn-block">Sign in</button>
    </form>
    <p class="auth-footnote">No code yet? Check your spam folder, or <a href="/login?email=${encodeURIComponent(email)}">start again</a>.</p>`,
    { shell: 'auth' });
}

// ------------- OTP consumer -------------
app.post('/otp', otpLimiter, requireCsrf, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const code = String(req.body.code || '').trim();
  const purpose = String(req.body.purpose || 'login');
  const next = safeNext(req.body.next);
  const user = await prisma.user.findUnique({ where: { email } });
  const otpErr = (msg) => layout('Verification', `
    <div class="auth-brand"><img src="/logo.png" alt="" width="26" height="26" style="border-radius:4px;"><span>Secure Mail</span></div>
    <div class="alert alert-danger">${esc(msg)}</div>
    <p class="auth-footnote"><a href="/login">Start over</a></p>`, { shell: 'auth' });
  if (!user) return res.status(400).send(otpErr('Unknown account.'));
  if (user.disabled) return res.status(403).send(otpErr('This account has been disabled.'));

  const otps = await prisma.otpToken.findMany({
    where: { userId: user.id, purpose, consumedAt: null, expiresAt: { gt: new Date() } },
    orderBy: { createdAt: 'desc' }, take: 5,
  });
  let matched = null;
  for (const t of otps) {
    if (t.attempts >= MAX_OTP_ATTEMPTS) continue;
    await prisma.otpToken.update({ where: { id: t.id }, data: { attempts: t.attempts + 1 } });
    if (await argon2.verify(t.codeHash, code).catch(() => false)) { matched = t; break; }
  }
  if (!matched) {
    await audit({ actorId: user.id, action: 'otp.fail', ip: clientIp(req), ua: clientUa(req) });
    return res.status(401).send(otpErr('That code is invalid or has expired.'));
  }
  await prisma.otpToken.update({ where: { id: matched.id }, data: { consumedAt: new Date() } });
  // Invalidate the pre-session and issue a fresh session (fixation protection).
  if (req.session) await prisma.session.delete({ where: { id: req.session.id } }).catch(() => {});
  await createSession(res, user, req);
  await audit({ actorId: user.id, action: 'login.otp.ok', ip: clientIp(req), ua: clientUa(req) });
  res.redirect(next);
});

// ------------- view message -------------
app.get('/view/:token', requireUser, async (req, res) => {
  const msg = await prisma.message.findUnique({
    where: { token: req.params.token }, include: { attachments: true },
  });
  if (!msg || msg.revokedAt) return res.status(404).send(layout('Not found', '<h1>Message not found</h1>'));
  if (msg.expiresAt < new Date()) return res.status(410).send(layout('Expired', '<h1>Expired.</h1>'));
  if (msg.recipientEmail.toLowerCase() !== req.user.email.toLowerCase())
    return res.status(403).send(layout('Forbidden', '<h1>This message isn’t addressed to you.</h1>'));

  let payload;
  try { payload = JSON.parse(decrypt({ iv: msg.bodyIv, tag: msg.bodyTag, cipher: msg.bodyCipher })); }
  catch { return res.status(500).send(layout('Error', '<p class="err">Could not decrypt.</p>')); }

  await prisma.message.update({
    where: { id: msg.id },
    data: { openCount: { increment: 1 }, firstOpenedAt: msg.firstOpenedAt ?? new Date() },
  });
  await audit({ actorId: req.user.id, action: 'message.view', target: msg.token, ip: clientIp(req), ua: clientUa(req) });

  const initials = (msg.senderEmail.split('@')[0].slice(0, 2)).toUpperCase();
  let bodyHtml;
  if (payload.html && payload.html.trim()) {
    // Sanitize before rendering. Strips scripts, iframes, event handlers, etc.
    const clean = sanitizeHtml(payload.html, SANITIZE_OPTS);
    bodyHtml = `<div class="msg-html">${clean}</div>`;
  } else {
    // Preserve original whitespace but wrap in a nicer styled block
    const text = (payload.text || '').replace(/</g, '&lt;');
    bodyHtml = `<div class="msg-text"><pre style="margin:0;font-family:inherit;font-size:15px;line-height:1.65;white-space:pre-wrap;word-wrap:break-word;">${text}</pre></div>`;
  }
  const fmtSize = n => n < 1024 ? `${n} B` : n < 1024*1024 ? `${(n/1024).toFixed(1)} KB` : `${(n/1024/1024).toFixed(1)} MB`;
  const fileIcon = '<svg class="att-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
  const atts = msg.attachments.length
    ? `<h2 class="card-title" style="margin-top:1.5rem;margin-bottom:.75rem;">Attachments (${msg.attachments.length})</h2>
       <div class="attachments">${msg.attachments.map(a =>
         `<a class="att-item" href="/view/${esc(msg.token)}/att/${a.idx}" download>
            ${fileIcon}
            <div class="att-meta">
              <span class="att-name">${esc(a.filename)}</span>
              <span class="att-detail">${esc(a.contentType)} · ${fmtSize(a.size)}</span>
            </div>
          </a>`).join('')}</div>`
    : '';

  const when = new Date(msg.createdAt).toLocaleString('en-US', {
    dateStyle: 'medium', timeStyle: 'short'
  });

  res.send(layout(msg.subject || 'Secure message', `
    <div class="page-head">
      <h1>${esc(msg.subject || '(no subject)')}</h1>
      <a href="/inbox" class="subtle">← Back to inbox</a>
    </div>
    <div class="card">
      <div class="msg-meta">
        <span class="avatar">${esc(initials)}</span>
        <div style="display:flex;flex-direction:column;">
          <span style="color:var(--text);font-weight:500;">${esc(msg.senderEmail)}</span>
          <span class="faint small">${esc(when)}</span>
        </div>
      </div>
      <div class="msg-body">${bodyHtml}</div>
      ${atts}
    </div>
    <p class="muted small" style="margin-top:1rem;">You’ll be signed out after ${SESSION_TTL_MIN} minutes of quiet.</p>`,
    { user: req.user, session: req.session }));
});

// ------------- attachment download -------------
app.get('/view/:token/att/:idx', requireUser, async (req, res) => {
  const idx = Number(req.params.idx);
  if (!Number.isInteger(idx) || idx < 0) return res.status(400).send('Bad index');
  const msg = await prisma.message.findUnique({
    where: { token: req.params.token }, include: { attachments: true },
  });
  if (!msg || msg.revokedAt) return res.status(404).send('Not found');
  if (msg.expiresAt < new Date()) return res.status(410).send('Expired');
  if (msg.recipientEmail.toLowerCase() !== req.user.email.toLowerCase()) return res.status(403).send('Forbidden');
  const att = msg.attachments.find(a => a.idx === idx);
  if (!att) return res.status(404).send('No such attachment');

  // Path-traversal defense: fully resolve both sides, require full === root
  // or a proper child (with the path separator suffix so /storage-x can't slip past).
  const root = path.resolve(process.env.STORAGE_ROOT || path.join(__dirname, '..', 'storage'));
  const full = path.resolve(root, att.storagePath);
  if (full !== root && !full.startsWith(root + path.sep)) return res.status(400).send('Bad path');

  let ciphertext;
  try { ciphertext = fs.readFileSync(full); }
  catch { return res.status(500).send('Blob missing'); }

  let plain;
  try { plain = decryptBuffer({ iv: att.iv, tag: att.tag, ciphertext }); }
  catch { return res.status(500).send('Decrypt failed'); }

  await audit({ actorId: req.user.id, action: 'attachment.download', target: `${msg.token}:${idx}`,
    ip: clientIp(req), ua: clientUa(req), meta: { filename: att.filename, size: att.size } });

  // Strip CR/LF/quote from the filename so it can't inject headers.
  const safeName = String(att.filename).replace(/[\r\n"\\]/g, '').slice(0, 200) || 'download';
  res.setHeader('Cache-Control', 'no-store, private');
  res.setHeader('Content-Type', att.contentType || 'application/octet-stream');
  res.setHeader('Content-Length', plain.length);
  res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.end(plain);
});

// ------------- logout -------------
app.post('/logout', requireCsrf, async (req, res) => {
  const sid = req.cookies[COOKIE_NAME];
  if (sid) await prisma.session.delete({ where: { id: sid } }).catch(() => {});
  res.clearCookie(COOKIE_NAME, { path: '/' });
  if (req.user) await audit({ actorId: req.user.id, action: 'logout', ip: clientIp(req), ua: clientUa(req) });
  res.redirect('/login');
});

// ------------- admin -------------
app.use('/admin', adminRouter);

// ------------- listen -------------
const port = Number(process.env.PORTAL_PORT || 3010);
app.listen(port, () => {
  console.log(`[portal] listening on http://localhost:${port} (prod=${IS_PROD})`);
});
