// Admin router mounted at /admin. Requires role=admin.
// Every state change writes an AuditLog row.
const express = require('express');
const prisma = require('./db');
const { esc, csrfField, requireCsrf, audit, passwordProblem, clientIp, clientUa } = require('./security');
const argon2 = require('argon2');
const crypto = require('crypto');

const router = express.Router();

function requireAdmin(req, res, next) {
  if (!req.user) return res.redirect('/admin/login?next=' + encodeURIComponent(req.originalUrl));
  if (req.user.role !== 'admin') return res.status(403).send('Forbidden');
  next();
}
// Public admin login page (before requireAdmin gate below).
router.get('/login', (req, res) => {
  const email = req.query.email || '';
  const next = req.query.next && req.query.next.startsWith('/admin') ? req.query.next : '/admin';
  res.send(`<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0f172a">
<title>Admin sign-in · Secure Mail</title>
<link rel="stylesheet" href="/static.css">
<style>
  .auth-wrap { background:
    radial-gradient(1200px 600px at 10% -10%, rgba(220,38,38,.14), transparent 60%),
    radial-gradient(900px 500px at 110% 110%, rgba(2,132,199,.10), transparent 55%),
    var(--bg); }
  .auth-brand { color: #dc2626; }
  .auth-brand .badge-admin { background: #dc2626; color: white; font-size: 11px; padding: 2px 8px; border-radius: 999px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; margin-left: .5rem; }
  button[type="submit"] { background: #dc2626 !important; color: white !important; }
</style>
</head><body class="shell-auth"><div class="auth-wrap"><main class="auth-card">
    <div class="auth-brand">
      <img src="/logo.png" alt="" width="26" height="26" style="border-radius:4px;"><span>Secure Mail</span>
      <span class="badge-admin">Admin</span>
    </div>
    <h1 class="auth-title">Administrator sign-in</h1>
    <p class="auth-sub">Admin-only sign-in. Regular users, head to the standard sign-in page.</p>
    <form method="post" action="/admin/login">
      <input type="hidden" name="next" value="${esc(next)}">
      <label>Admin email
        <input name="email" type="email" required value="${esc(email)}" autocomplete="email" autofocus>
      </label>
      <label>Password
        <input name="password" type="password" required autocomplete="current-password">
      </label>
      <button type="submit" class="btn-block">Continue</button>
    </form>
    <p class="auth-footnote">Not an administrator? <a href="/login">Regular sign-in</a></p>
</main></div></body></html>`);
});

router.post('/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const nextRaw = String(req.body.next || '/admin');
  const next = nextRaw.startsWith('/admin') ? nextRaw : '/admin';

  const user = await prisma.user.findUnique({ where: { email } });
  const dummy = '$argon2id$v=19$m=65536,t=3,p=4$YWFhYWFhYWFhYWFhYWFhYQ$AAAAAAAAAAAAAAAAAAAAAA';
  const hash = user?.passwordHash || dummy;
  const ok = await argon2.verify(hash, password).catch(() => false);

  const bad = () => res.status(401).send(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin sign-in</title><link rel="stylesheet" href="/static.css"><body class="shell-auth"><div class="auth-wrap"><main class="auth-card"><div class="alert alert-danger">Invalid credentials.</div><p class="auth-footnote"><a href="/admin/login">Try again</a></p></main></div></body>`);

  // Refuse non-admin accounts here without confirming their existence.
  if (!user || !ok || user.disabled || user.role !== 'admin') {
    if (user) {
      const fails = user.failedLoginCount + 1;
      const lock = fails >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null;
      await prisma.user.update({ where: { id: user.id }, data: { failedLoginCount: fails, lockedUntil: lock } });
      await audit({ actorId: user.id, action: user.role !== 'admin' ? 'admin.login.refused.not_admin' : 'admin.login.fail', ip: clientIp(req), ua: clientUa(req) });
    }
    return bad();
  }
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    return res.status(423).send(`<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="/static.css"><body class="shell-auth"><div class="auth-wrap"><main class="auth-card"><div class="alert alert-danger">Account locked temporarily.</div></main></div></body>`);
  }

  await prisma.user.update({ where: { id: user.id }, data: { failedLoginCount: 0, lockedUntil: null } });

  // Issue OTP identical to portal.js pattern
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  const codeHash = await argon2.hash(code, { type: argon2.argon2id });
  const expiresAt = new Date(Date.now() + (Number(process.env.OTP_TTL_MINUTES || 10)) * 60 * 1000);
  await prisma.otpToken.create({ data: { userId: user.id, codeHash, purpose: 'admin_login', expiresAt } });

  // Send OTP via the shared mailer
  const { sendOtp } = require('./mailer');
  try { await sendOtp({ to: user.email, code, purpose: 'admin_login' }); } catch (e) { console.error('[admin] sendOtp failed', e && e.message); }

  await audit({ actorId: user.id, action: 'admin.login.password.ok', ip: clientIp(req), ua: clientUa(req) });

  // Pre-session to carry CSRF into the OTP form
  const prisma2 = prisma;
  const { newToken } = require('./crypto');
  const sid = newToken(24);
  const csrfToken = newToken(24);
  const sessExpires = new Date(Date.now() + (Number(process.env.SESSION_TTL_MINUTES || 30)) * 60 * 1000);
  const session = await prisma2.session.create({
    data: { id: sid, userId: user.id, csrfToken, ip: clientIp(req), ua: clientUa(req), expiresAt: sessExpires },
  });
  const IS_PROD = process.env.NODE_ENV === 'production';
  const cookieName = IS_PROD ? '__Host-sid' : 'sid';
  res.cookie(cookieName, sid, { httpOnly: true, sameSite: 'lax', secure: IS_PROD, path: '/', maxAge: (Number(process.env.SESSION_TTL_MINUTES || 30)) * 60 * 1000 });

  // OTP form for admins (posts to /admin/otp)
  res.send(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin verification</title><link rel="stylesheet" href="/static.css"><body class="shell-auth"><div class="auth-wrap"><main class="auth-card">
    <div class="auth-brand"><img src="/logo.png" alt="" width="26" height="26" style="border-radius:4px;"><span>Secure Mail</span><span style="background: #dc2626; color: white; font-size: 11px; padding: 2px 8px; border-radius: 999px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; margin-left: .5rem;">Admin</span></div>
    <h1 class="auth-title">Check your email</h1>
    <p class="auth-sub">We sent a 6-digit code to <b>${esc(user.email)}</b>.</p>
    <form method="post" action="/admin/otp">
      <input type="hidden" name="_csrf" value="${esc(csrfToken)}">
      <input type="hidden" name="next" value="${esc(next)}">
      <input type="hidden" name="email" value="${esc(user.email)}">
      <label>Verification code
        <input name="code" class="otp-input" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autofocus autocomplete="one-time-code" placeholder="000000">
      </label>
      <button type="submit" class="btn-block" style="background: #dc2626; color: white;">Sign in</button>
    </form>
    <p class="auth-footnote"><a href="/admin/login">Start over</a></p>
</main></div></body>`);
});

router.post('/otp', requireCsrf, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const code = String(req.body.code || '').trim();
  const nextRaw = String(req.body.next || '/admin');
  const next = nextRaw.startsWith('/admin') ? nextRaw : '/admin';

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || user.role !== 'admin' || user.disabled) {
    return res.status(403).send('<link rel="stylesheet" href="/static.css"><body class="shell-auth"><div class="auth-wrap"><main class="auth-card"><div class="alert alert-danger">Session invalid.</div><p><a href="/admin/login">Start over</a></p></main></div></body>');
  }

  const otps = await prisma.otpToken.findMany({
    where: { userId: user.id, purpose: 'admin_login', consumedAt: null, expiresAt: { gt: new Date() } },
    orderBy: { createdAt: 'desc' }, take: 5,
  });
  let matched = null;
  for (const t of otps) {
    if (t.attempts >= 5) continue;
    await prisma.otpToken.update({ where: { id: t.id }, data: { attempts: t.attempts + 1 } });
    if (await argon2.verify(t.codeHash, code).catch(() => false)) { matched = t; break; }
  }
  if (!matched) {
    await audit({ actorId: user.id, action: 'admin.otp.fail', ip: clientIp(req), ua: clientUa(req) });
    return res.status(401).send('<link rel="stylesheet" href="/static.css"><body class="shell-auth"><div class="auth-wrap"><main class="auth-card"><div class="alert alert-danger">Invalid or expired code.</div><p class="auth-footnote"><a href="/admin/login">Start over</a></p></main></div></body>');
  }
  await prisma.otpToken.update({ where: { id: matched.id }, data: { consumedAt: new Date() } });

  // Rotate session (fixation defense)
  const { newToken } = require('./crypto');
  const IS_PROD = process.env.NODE_ENV === 'production';
  const cookieName = IS_PROD ? '__Host-sid' : 'sid';
  const oldSid = req.cookies?.[cookieName];
  if (oldSid) await prisma.session.delete({ where: { id: oldSid } }).catch(() => {});

  const sid = newToken(24);
  const csrfToken = newToken(24);
  const sessExpires = new Date(Date.now() + (Number(process.env.SESSION_TTL_MINUTES || 30)) * 60 * 1000);
  await prisma.session.create({
    data: { id: sid, userId: user.id, csrfToken, ip: clientIp(req), ua: clientUa(req), expiresAt: sessExpires },
  });
  res.cookie(cookieName, sid, { httpOnly: true, sameSite: 'lax', secure: IS_PROD, path: '/', maxAge: (Number(process.env.SESSION_TTL_MINUTES || 30)) * 60 * 1000 });

  await audit({ actorId: user.id, action: 'admin.login.otp.ok', ip: clientIp(req), ua: clientUa(req) });
  res.redirect(next);
});

router.use(requireAdmin);

const LOCK_SVG_A = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
const FAVICON_A = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNGY0NmU1IiBzdHJva2Utd2lkdGg9IjIuNSIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cmVjdCB4PSIzIiB5PSIxMSIgd2lkdGg9IjE4IiBoZWlnaHQ9IjExIiByeD0iMiIvPjxwYXRoIGQ9Ik03IDExVjdhNSA1IDAgMCAxIDEwIDB2NCIvPjwvc3ZnPg==';
const CSS_VERSION_A = 2;

function shell(title, body, req, active) {
  const items = [
    ['/admin',              'Dashboard',     'a-dash'],
    ['/admin/messages',     'Messages',      'a-msgs'],
    ['/admin/users',        'Users',         'a-users'],
    ['/admin/sessions',     'Sessions',      'a-sess'],
    ['/admin/mail-settings','Mail settings', 'a-mail'],
    ['/admin/audit',        'Audit log',     'a-audit'],
  ];
  const nav = `<div class="admin-nav">${items.map(([href, label, key]) =>
    `<a href="${href}"${active === key ? ' class="active"' : ''}>${label}</a>`).join('')}</div>`;
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#dc2626">
<title>Admin · ${esc(title)} · Secure Mail</title>
<link rel="icon" href="/logo.png">
<link rel="stylesheet" href="/static.css?v=${CSS_VERSION_A}">
</head><body class="shell-app">
<header class="topbar">
  <div class="brand"><img src="/logo.png" alt="" width="26" height="26" style="border-radius:4px;"><span>Secure Mail</span></div>
  <nav class="topbar-nav">
    <a href="/inbox">Inbox</a>
    <a href="/admin">Admin</a>
  </nav>
  <div class="topbar-user">
    <span class="user-email">${esc(req.user.email)}</span>
    <span class="chip chip-accent">admin</span>
    <form method="post" action="/logout" class="inline">
      ${csrfField(req.session)}
      <button type="submit" class="btn btn-ghost btn-sm">Sign out</button>
    </form>
  </div>
</header>
<main class="app-main">${nav}${body}</main>
</body></html>`;
}

// ---------- dashboard ----------
router.get('/', async (req, res) => {
  const [messages, users, activeSessions, opens24h, revoked] = await Promise.all([
    prisma.message.count(),
    prisma.user.count(),
    prisma.session.count({ where: { expiresAt: { gt: new Date() } } }),
    prisma.auditLog.count({ where: { action: 'message.view', ts: { gt: new Date(Date.now() - 86400e3) } } }),
    prisma.message.count({ where: { revokedAt: { not: null } } }),
  ]);
  const metric = (label, value) =>
    `<div class="metric"><div class="metric-label">${label}</div><div class="metric-value">${value}</div></div>`;
  res.send(shell('Dashboard', `
    <div class="page-head"><h1>Dashboard</h1><span class="subtle">Live metrics</span></div>
    <div class="metrics">
      ${metric('Total messages', messages)}
      ${metric('Revoked', revoked)}
      ${metric('Total users', users)}
      ${metric('Active sessions', activeSessions)}
      ${metric('Opens (24h)', opens24h)}
    </div>`, req, 'a-dash'));
});

// ---------- messages ----------
router.get('/messages', async (req, res) => {
  const msgs = await prisma.message.findMany({
    orderBy: { createdAt: 'desc' }, take: 100,
    include: { attachments: true },
  });
  const stateChip = m => m.revokedAt
    ? '<span class="chip chip-danger">revoked</span>'
    : m.expiresAt < new Date()
      ? '<span class="chip">expired</span>'
      : '<span class="chip chip-success">active</span>';
  const rows = msgs.map(m => `<tr>
    <td class="muted small">${esc(m.createdAt.toISOString().slice(0,16).replace('T',' '))}</td>
    <td><span class="mono">${esc(m.senderEmail)}</span> <span class="faint">→</span> <span class="mono">${esc(m.recipientEmail)}</span></td>
    <td>${esc(m.subject || '(no subject)')}</td>
    <td>${m.attachments.length}</td>
    <td>${m.openCount}</td>
    <td>${stateChip(m)}</td>
    <td class="actions">
      ${m.revokedAt ? '' : `
        <form method="post" action="/admin/messages/${esc(m.id)}/revoke">${csrfField(req.session)}<button class="btn-danger btn-sm">Revoke</button></form>
        <form method="post" action="/admin/messages/${esc(m.id)}/extend">${csrfField(req.session)}<button class="secondary btn-sm">+7d</button></form>
      `}
    </td>
  </tr>`).join('');
  res.send(shell('Messages', `
    <div class="page-head"><h1>Messages</h1><span class="subtle">Recent ${msgs.length}</span></div>
    <div class="card" style="padding:0;overflow:hidden;">
      <table><thead><tr><th>Created</th><th>From → To</th><th>Subject</th><th>Att</th><th>Opens</th><th>Status</th><th></th></tr></thead>
      <tbody>${rows}</tbody></table>
    </div>`, req, 'a-msgs'));
});

router.post('/messages/:id/revoke', requireCsrf, async (req, res) => {
  const m = await prisma.message.update({ where: { id: req.params.id }, data: { revokedAt: new Date() } });
  await audit({ actorId: req.user.id, action: 'message.revoke', target: m.token, ip: clientIp(req), ua: clientUa(req) });
  res.redirect('/admin/messages');
});

router.post('/messages/:id/extend', requireCsrf, async (req, res) => {
  const m = await prisma.message.findUnique({ where: { id: req.params.id } });
  const base = m.expiresAt > new Date() ? m.expiresAt : new Date();
  const newExp = new Date(base.getTime() + 7 * 24 * 3600 * 1000);
  await prisma.message.update({ where: { id: req.params.id }, data: { expiresAt: newExp } });
  await audit({ actorId: req.user.id, action: 'message.extend', target: m.token,
    ip: clientIp(req), ua: clientUa(req), meta: { newExpiry: newExp.toISOString() } });
  res.redirect('/admin/messages');
});

// ---------- users ----------
router.get('/users', async (req, res) => {
  const users = await prisma.user.findMany({ orderBy: { createdAt: 'desc' }, take: 200 });
  const rows = users.map(u => `<tr>
    <td><span class="mono">${esc(u.email)}</span></td>
    <td>${u.role === 'admin' ? '<span class="chip chip-accent">admin</span>' : '<span class="chip">user</span>'}${u.disabled ? ' <span class="chip chip-danger">disabled</span>' : ''}</td>
    <td>${u.failedLoginCount}${u.lockedUntil && u.lockedUntil > new Date() ? ' <span class="chip chip-warning">locked</span>' : ''}</td>
    <td class="muted small">${esc(u.createdAt.toISOString().slice(0,10))}</td>
    <td class="actions">
      <form method="post" action="/admin/users/${esc(u.id)}/toggle">${csrfField(req.session)}<button class="btn-sm">${u.disabled ? 'Enable' : 'Disable'}</button></form>
      <form method="post" action="/admin/users/${esc(u.id)}/role">${csrfField(req.session)}
        <input type="hidden" name="role" value="${u.role === 'admin' ? 'user' : 'admin'}">
        <button class="secondary btn-sm">${u.role === 'admin' ? 'Demote' : 'Make admin'}</button></form>
      <form method="post" action="/admin/users/${esc(u.id)}/reset-password" style="display:inline-flex;gap:.25rem;align-items:center;">${csrfField(req.session)}
        <input name="password" type="password" placeholder="New password" required minlength="12" style="width:150px;padding:.3rem .5rem;">
        <button class="btn-sm">Set</button></form>
      <form method="post" action="/admin/users/${esc(u.id)}/kill-sessions">${csrfField(req.session)}<button class="secondary btn-sm">Kill sessions</button></form>
    </td>
  </tr>`).join('');
  res.send(shell('Users', `
    <div class="page-head"><h1>Users</h1><span class="subtle">${users.length} total</span></div>
    <div class="card" style="padding:0;overflow:hidden;">
      <table><thead><tr><th>Email</th><th>Role</th><th>Fails</th><th>Since</th><th></th></tr></thead><tbody>${rows}</tbody></table>
    </div>`, req, 'a-users'));
});

router.post('/users/:id/toggle', requireCsrf, async (req, res) => {
  const u = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!u) return res.status(404).send('No user');
  if (u.id === req.user.id) return res.status(400).send('Cannot disable yourself');
  await prisma.user.update({ where: { id: u.id }, data: { disabled: !u.disabled } });
  if (!u.disabled) await prisma.session.deleteMany({ where: { userId: u.id } });
  await audit({ actorId: req.user.id, action: u.disabled ? 'user.enable' : 'user.disable', target: u.id,
    ip: clientIp(req), ua: clientUa(req) });
  res.redirect('/admin/users');
});

router.post('/users/:id/role', requireCsrf, async (req, res) => {
  const role = req.body.role === 'admin' ? 'admin' : 'user';
  if (req.params.id === req.user.id && role !== 'admin') return res.status(400).send('Cannot demote yourself');
  await prisma.user.update({ where: { id: req.params.id }, data: { role } });
  await audit({ actorId: req.user.id, action: 'user.role', target: req.params.id,
    ip: clientIp(req), ua: clientUa(req), meta: { role } });
  res.redirect('/admin/users');
});

router.post('/users/:id/reset-password', requireCsrf, async (req, res) => {
  const password = String(req.body.password || '');
  const err = passwordProblem(password);
  if (err) return res.status(400).send(err);
  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
  await prisma.user.update({ where: { id: req.params.id }, data: { passwordHash, failedLoginCount: 0, lockedUntil: null } });
  await prisma.session.deleteMany({ where: { userId: req.params.id } });
  await audit({ actorId: req.user.id, action: 'user.reset-password', target: req.params.id,
    ip: clientIp(req), ua: clientUa(req) });
  res.redirect('/admin/users');
});

router.post('/users/:id/kill-sessions', requireCsrf, async (req, res) => {
  await prisma.session.deleteMany({ where: { userId: req.params.id } });
  await audit({ actorId: req.user.id, action: 'user.kill-sessions', target: req.params.id,
    ip: clientIp(req), ua: clientUa(req) });
  res.redirect('/admin/users');
});

// ---------- sessions ----------
router.get('/sessions', async (req, res) => {
  const ss = await prisma.session.findMany({
    orderBy: { lastSeenAt: 'desc' }, take: 200, include: { user: true },
  });
  const rows = ss.map(s => `<tr>
    <td><span class="mono">${esc(s.user.email)}</span></td>
    <td class="mono small">${esc(s.ip || '')}</td>
    <td class="faint small">${esc((s.ua || '').slice(0, 60))}</td>
    <td class="muted small">${esc(s.lastSeenAt.toISOString().slice(0,16).replace('T',' '))}</td>
    <td class="muted small">${esc(s.expiresAt.toISOString().slice(0,16).replace('T',' '))}</td>
    <td class="actions"><form method="post" action="/admin/sessions/${esc(s.id)}/kill">${csrfField(req.session)}<button class="btn-danger btn-sm">Kill</button></form></td>
  </tr>`).join('');
  res.send(shell('Sessions', `
    <div class="page-head"><h1>Active sessions</h1><span class="subtle">${ss.length} live</span></div>
    <div class="card" style="padding:0;overflow:hidden;">
      <table><thead><tr><th>User</th><th>IP</th><th>User agent</th><th>Last seen</th><th>Expires</th><th></th></tr></thead><tbody>${rows}</tbody></table>
    </div>`, req, 'a-sess'));
});

router.post('/sessions/:id/kill', requireCsrf, async (req, res) => {
  await prisma.session.delete({ where: { id: req.params.id } }).catch(() => {});
  await audit({ actorId: req.user.id, action: 'session.kill', target: req.params.id,
    ip: clientIp(req), ua: clientUa(req) });
  res.redirect('/admin/sessions');
});

// ---------- audit ----------
router.get('/audit', async (req, res) => {
  const events = await prisma.auditLog.findMany({
    orderBy: { ts: 'desc' }, take: 200, include: { actor: true },
  });
  const actionChip = a => {
    if (a.endsWith('.fail')) return `<span class="chip chip-danger">${esc(a)}</span>`;
    if (a.startsWith('login.') || a.startsWith('user.signup')) return `<span class="chip chip-success">${esc(a)}</span>`;
    if (a.startsWith('user.') || a.startsWith('message.revoke') || a.startsWith('session.kill')) return `<span class="chip chip-warning">${esc(a)}</span>`;
    return `<span class="chip">${esc(a)}</span>`;
  };
  const rows = events.map(e => `<tr>
    <td class="muted small mono">${esc(e.ts.toISOString().slice(0,19).replace('T',' '))}</td>
    <td class="mono small">${esc(e.actor?.email || '')}</td>
    <td>${actionChip(e.action)}</td>
    <td class="mono small">${esc((e.target || '').slice(0, 40))}</td>
    <td class="mono small">${esc(e.ip || '')}</td>
    <td class="faint small">${esc((e.meta || '').slice(0, 60))}</td>
  </tr>`).join('');
  res.send(shell('Audit', `
    <div class="page-head"><h1>Audit log</h1><span class="subtle">Last ${events.length}</span></div>
    <div class="card" style="padding:0;overflow:hidden;">
      <table><thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>IP</th><th>Meta</th></tr></thead><tbody>${rows}</tbody></table>
    </div>`, req, 'a-audit'));
});


// ---------- mail settings ----------
router.get('/mail-settings', async (req, res) => {
  const cfg = await prisma.mailConfig.findUnique({ where: { id: 'main' } });
  const has = Boolean(cfg && cfg.smtpPassCt);
  res.send(shell('Mail Settings', `
    <div class="page-head">
      <h1>Mail Settings</h1>
      <span class="subtle">Where our system sends OTPs, secure notifications, and pass-through mail from</span>
    </div>

    <div class="card">
      <form method="post" action="/admin/mail-settings" class="stack" style="max-width: 640px;">
        ${csrfField(req.session)}
        <label>SMTP Host
          <input name="smtpHost" required value="${esc(cfg?.smtpHost || 'smtp.zeptomail.com')}">
        </label>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
          <label>Port
            <input name="smtpPort" type="number" required value="${cfg?.smtpPort || 587}">
          </label>
          <label style="align-self:end;">
            <input type="checkbox" name="smtpSecure" value="1" ${cfg?.smtpSecure ? 'checked' : ''}>
            SSL (implicit TLS on 465)
          </label>
        </div>
        <label>Username
          <input name="smtpUser" value="${esc(cfg?.smtpUser || 'emailapikey')}">
          <span class="field-hint">ZeptoMail uses the literal string <span class="mono">emailapikey</span></span>
        </label>
        <label>Password / API token
          <input name="smtpPass" type="password" placeholder="${has ? '••••••••  (leave blank to keep current)' : 'Mail Agent token from ZeptoMail'}" autocomplete="new-password">
          <span class="field-hint">Encrypted at rest with the app's message key.</span>
        </label>
        <label>Sender name (used only for our own emails)
          <input name="fromName" value="${esc(cfg?.fromName || 'Secure Mail')}">
        </label>
        <label>Sender email (used only for our own emails)
          <input name="fromEmail" type="email" required value="${esc(cfg?.fromEmail || 'secure@Secure.org')}">
          <span class="field-hint">This is the "From" on notifications and login codes the portal sends. Regular pass-through mail keeps whoever originally sent it.</span>
        </label>
        <label style="display:flex;align-items:center;gap:8px;">
          <input type="checkbox" name="enabled" value="1" ${cfg?.enabled ? 'checked' : ''}>
          Enabled (turn off to log outbound mail instead of sending it, useful while testing)
        </label>
        <div style="display:flex;gap:8px;">
          <button type="submit">Save settings</button>
          <button type="submit" formaction="/admin/mail-settings/test" formmethod="post" class="secondary">Save and send test</button>
        </div>
      </form>
    </div>
    ${cfg && cfg.updatedAt ? `<p class="muted small" style="margin-top:1rem;">Last updated ${esc(new Date(cfg.updatedAt).toLocaleString('en-US'))}.</p>` : ''}
  `, req, 'a-mail'));
});

router.post('/mail-settings', requireCsrf, async (req, res) => {
  await savefMailConfig(req);
  await audit({ actorId: req.user.id, action: 'admin.mail.save', ip: clientIp(req), ua: clientUa(req) });
  res.redirect('/admin/mail-settings');
});

router.post('/mail-settings/test', requireCsrf, async (req, res) => {
  await savefMailConfig(req);
  const { sendOtp, invalidateCache } = require('./mailer');
  invalidateCache();
  let ok = true; let errMsg = '';
  try {
    await sendOtp({ to: req.user.email, code: '123456', purpose: 'admin-mail-test' });
  } catch (e) { ok = false; errMsg = e && e.message || String(e); }
  await audit({ actorId: req.user.id, action: ok ? 'admin.mail.test.ok' : 'admin.mail.test.fail', ip: clientIp(req), ua: clientUa(req), meta: { errMsg } });
  res.send(shell('Mail Settings', `
    <div class="page-head"><h1>Mail Settings</h1></div>
    <div class="alert alert-${ok ? 'success' : 'danger'}">
      ${ok
        ? `Test email sent to ${esc(req.user.email)}. Check your inbox.`
        : `Test failed: <span class="mono">${esc(errMsg)}</span>`}
    </div>
    <p><a href="/admin/mail-settings">Back to settings</a></p>
  `, req, 'a-mail'));
});

async function savefMailConfig(req) {
  const { encrypt } = require('./crypto');
  const smtpPass = String(req.body.smtpPass || '').trim();
  const existing = await prisma.mailConfig.findUnique({ where: { id: 'main' } });
  const passEnc = smtpPass
    ? encrypt(smtpPass)
    : (existing ? { iv: existing.smtpPassIv, tag: existing.smtpPassTag, cipher: existing.smtpPassCt } : { iv: '', tag: '', cipher: '' });
  const data = {
    smtpHost: String(req.body.smtpHost || '').trim(),
    smtpPort: Number(req.body.smtpPort || 587),
    smtpSecure: req.body.smtpSecure === '1' || req.body.smtpSecure === 'on',
    smtpUser: String(req.body.smtpUser || '').trim(),
    smtpPassIv: passEnc.iv,
    smtpPassTag: passEnc.tag,
    smtpPassCt: passEnc.cipher,
    fromName: String(req.body.fromName || 'Secure Mail').trim(),
    fromEmail: String(req.body.fromEmail || '').trim(),
    enabled: req.body.enabled === '1' || req.body.enabled === 'on',
    updatedById: req.user.id,
  };
  await prisma.mailConfig.upsert({ where: { id: 'main' }, update: data, create: { id: 'main', ...data } });
  const { invalidateCache } = require('./mailer');
  invalidateCache();
}

module.exports = router;
