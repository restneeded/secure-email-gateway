# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Fixed

- Attachment download path check is now a proper resolved-prefix comparison instead of a raw `startsWith`, and it requires the trailing path separator so paths like `/storage-other` can't slip past `/storage`.
- CR/LF and quotes are stripped from attachment filenames before they hit `Content-Disposition`.
- `createSession` now mutates `req.session` and `req.user` for the current request so the OTP form can embed a CSRF token when rendered on the same response that just issued the session.
- Authenticated responses now carry `Cache-Control: no-store, private`.

## [0.2.0] 2026-07-23

### Added

- Attachments: each file gets its own AES-256-GCM IV and tag, blobs live at `storage/<token>/<idx>.bin`, download route at `/view/:token/att/:idx`.
- Admin panel at `/admin`: dashboard, messages (revoke, extend by 7 days), users (disable, promote, reset password, kill sessions), sessions (kill one), audit log.
- `scripts/create-admin.js` for bootstrapping the first admin.
- Portal hardening:
  - Argon2id passwords, 12 character minimum with a class-mix requirement.
  - Password plus email OTP MFA on every login. OTP is hashed, capped at 5 attempts, 10 minute TTL.
  - Opaque sliding sessions, IP+UA bound in production, `__Host-` cookie prefix.
  - CSRF synchronizer token on every form.
  - `helmet` with a strict CSP and HSTS.
  - `express-rate-limit` on login, signup, and OTP endpoints.
  - 5 failed logins locks the account for 15 minutes.
  - Fresh session issued after OTP success (session fixation defense).
  - Open-redirect protection on `?next=`.
  - Dummy Argon2 verify on unknown emails to blunt enumeration.
  - Audit log entries for login events and every admin action.
- Dockerfile and `docker-compose.yml` for a one-command demo.
- MIT license, security policy, contributing guide, code of conduct, GitHub CI, issue and PR templates.

## [0.1.0] 2026-07-23

### Added

- SMTP submission gateway that watches the subject line for a configurable trigger keyword (`[secure]` by default).
- AES-256-GCM encryption of the message body, stored in SQLite via Prisma.
- Portal with signup, password login, email OTP, and a `/view/:token` route that decrypts and renders the body for the intended recipient.
- Pass-through relay for mail without the trigger keyword.
- `MAIL_MODE=console` to log outbound mail instead of sending it.
