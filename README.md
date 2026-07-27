# secure-email-gateway

Self-hosted "encrypted email" without the SaaS bill. Runs on one small VPS (or an old NUC in a closet), stitches together a bunch of free tiers, and gives you a portal recipients can log into to read messages.

You keep normal email working the way it always did. Anywhere someone types `[secure]` in the subject, the gateway holds the body and attachments, encrypts them at rest, and mails the recipient a portal link instead. The recipient signs up (or signs in), gets a 6-digit code by email, and reads the message on your domain, not a vendor's.

Everything else passes through untouched.

## Why bother

The commercial "secure message" portals cost real money and lock your outbound flow behind their infra. This is roughly the same shape as those, just yours. Nice for a small clinic, a law office, a school district, or anyone who has to move a few sensitive things a week and doesn't want a subscription for it.

It's not a full HIPAA compliance package on its own. It gives you the technical safeguards (encryption at rest, TLS in transit, audit logging, session hygiene, MFA on every login). The rest of compliance is still on you: BAAs with your relay, physical controls on where you host it, your written policies, staff training.

## What you need (all free tiers work)

A domain name. Anything you already own is fine. You'll use two hostnames on it: `portal.yourdomain.com` for the web portal, `smtp.yourdomain.com` for the SMTP intake. You can rename either.

A small VPS or box you own. 1 vCPU / 1 GB RAM handles this comfortably for a small org. If HIPAA or similar matters to you, own the box or get a signed BAA with your hosting provider.

Docker + Docker Compose on it.

A relay to actually deliver mail. [ZeptoMail](https://www.zoho.com/zeptomail/) has a free tier and is what this project was originally set up against. Postmark, SES, Mailgun, or your own Postfix all work too, anything you can hit with SMTP AUTH.

Optionally, [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-tunnel/) (free) if you don't want to open port 443 on your router. Recommended.

Let's Encrypt for the SMTP TLS cert (`certbot` with the DNS challenge if 80 is closed).

## How it works

```
  sender's mail client
           |
           v
  gateway (SMTP :587)  --- does the subject contain [secure]?
           |                    no  -> forward to your relay, done
           |                    yes -> keep going
           v
  encrypt body            -> SQLite row
  encrypt each attachment -> storage/<token>/<idx>.bin
  send a "you have a secure message" notification
           |
           v
  recipient opens the link
  signs up or signs in
  enters a 6-digit code from their email
  reads the message, downloads any files
```

## Set it up

There's a longer walkthrough in [`docs/setup.md`](docs/setup.md) covering DNS, certs, Cloudflare Tunnel, and the outbound relay. Short version:

```bash
git clone https://github.com/restneeded/secure-email-gateway.git
cd secure-email-gateway
cp .env.example .env
# edit .env: SESSION_SECRET, MESSAGE_KEY_HEX, PORTAL_ORIGIN, INITIAL_ADMIN_EMAIL
docker compose up -d
```

Then in the admin panel, plug in your outbound relay (host, port, `emailapikey` username + token for ZeptoMail, or whatever your relay expects) and you're delivering.

Point your outbound mail through the gateway either by SMTP forwarding from your existing mail provider (Google Workspace, Zoho, Microsoft 365 all support outbound-gateway routing) or by pointing individual clients at it directly.

## Security posture

Argon2id passwords, 12 char minimum with a class mix. Password plus an emailed 6-digit code every sign-in — the code is hashed and rate-limited too. Sessions are opaque random IDs on a `__Host-` cookie, bound to IP + User-Agent, sliding 30-minute window. CSRF on every form. Rate limits on login, signup, and OTP. Five bad logins locks the account for 15 minutes.

Every login, logout, view, download, and admin action lands in an audit log with IP + User-Agent. Message bodies get sanitized before render, attachments come down as `Content-Disposition: attachment` with `nosniff`. helmet handles the usual headers (strict CSP, HSTS in prod, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`).

Message bodies and attachments are AES-256-GCM encrypted at rest with a key you set in `.env`. Lose that key and the messages are gone — that's the design.

## Admin

`/admin` gives you dashboard counts, a message list with revoke + "extend by 7 days", a user list (disable, promote, reset password, kill all sessions), an active sessions view with revoke, an audit log, and a mail-settings page for the outbound relay creds (stored encrypted with your `MESSAGE_KEY_HEX`).

Admin sign-in is on its own path (`/admin/login`) with the same password + emailed code flow as regular users.

## Contributing

Issues and PRs welcome. Keep the surface small and boring, the goal is a small org can run this and understand it end to end.

## License

MIT.
