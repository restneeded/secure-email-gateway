# Contributing

Thanks for looking at this. A few things to know before you send a PR.

## What I like

Small, focused changes. One fix or one feature per PR. Match the existing style: CommonJS, no build step, plain Express, minimal deps. If you think a refactor is needed, open an issue first so we can talk about it before you write a bunch of code.

New dependencies need a reason in the PR description. Anything that touches auth, crypto, or the admin routes deserves a second set of eyes, so tag me and expect some back-and-forth.

## Getting set up

```bash
git clone https://github.com/restneeded/secure-email-gateway.git
cd secure-email-gateway
cp .env.example .env
node -e "console.log('MESSAGE_KEY_HEX=' + require('crypto').randomBytes(32).toString('hex'))"  # paste into .env
npm install
npx prisma generate
npm run db:push
npm run create-admin -- you@example.com
npm run dev
```

Keep `MAIL_MODE=console` (the default) while you're iterating so no real mail goes out.

## Tests

`npm test` runs the node test runner. Tests live in `test/`. If you're changing `src/crypto.js`, `src/security.js`, or anything in the login/OTP path in `src/portal.js`, please add coverage.

## Commits

Short, imperative subject lines. "Fix path traversal in attachment download", not "Fixed path traversal". If you use conventional commits, cool, but I don't require it.

## Security bugs

Please don't file them as public issues. See [SECURITY.md](SECURITY.md).
