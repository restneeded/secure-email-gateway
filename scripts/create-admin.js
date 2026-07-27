// Bootstrap or promote an admin.
// Usage:
//   node scripts/create-admin.js you@Secure.org [password]
// If no password is given, one is generated and printed once.
require('dotenv').config();
const crypto = require('crypto');
const argon2 = require('argon2');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { passwordProblem } = require('../src/security');

async function main() {
  const email = (process.argv[2] || '').toLowerCase().trim();
  let password = process.argv[3];
  if (!email) { console.error('usage: node scripts/create-admin.js <email> [password]'); process.exit(1); }
  if (!password) {
    password = crypto.randomBytes(12).toString('base64url') + 'Aa1!'; // guaranteed to pass policy
  }
  const err = passwordProblem(password);
  if (err) { console.error(err); process.exit(1); }
  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
  const user = await prisma.user.upsert({
    where: { email },
    update: { role: 'admin', disabled: false, passwordHash, failedLoginCount: 0, lockedUntil: null },
    create: { email, passwordHash, role: 'admin' },
  });
  console.log('\nAdmin ready:');
  console.log('  email:   ', user.email);
  console.log('  password:', password);
  console.log('\nSign in at the portal and change the password from the admin page.\n');
  process.exit(0);
}
main().catch(e => { console.error(e); process.exit(1); });
