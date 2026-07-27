## What this changes

<!-- One or two sentences. -->

## Why

<!-- Link the issue or describe the motivation. -->

## Verification

- [ ] `node --check` passes on every touched file
- [ ] `npx prisma validate` passes
- [ ] Smoke test with swaks (or docker-compose): send a `[secure]` mail end-to-end
- [ ] Admin actions still work if you touched `src/admin.js`
- [ ] No new deps (or listed with justification)

## Security notes

<!-- If this touches auth, crypto, or admin — describe the threat model impact. -->
