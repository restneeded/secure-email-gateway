# Security policy

## What's supported

Pre 1.0, so only the `main` branch and the latest tag get security fixes. If you're on an older tag, please update before reporting.

## Reporting something

Please don't open a public issue for security problems. Two better options:

Email me at **rest@rest.ac** with the details, or open a private security advisory in the repo's Security tab.

Include enough for me to reproduce it: what happens, a proof of concept if you have one, and which commit or release you saw it on. If you have a patch in mind, mention it, but it's not required.

You'll hear back within 72 hours. If it's a real issue, I'll aim to have a fix out inside 14 days of triage. High-severity stuff moves faster.

## Scope

In scope: anything in this repo. The gateway, the portal, the admin panel, the crypto helpers, the schema, the Dockerfile, the CI workflow.

Out of scope: how you personally deployed it (your nginx, your Cloudflare, your MTA config), bugs in upstream dependencies (please report those to the dependency), and pure volumetric DoS without an amplification angle.

## Credit

If you want your name on the fix, say so and I'll list it here after the release ships.
