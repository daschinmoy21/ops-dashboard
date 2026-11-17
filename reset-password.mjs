#!/usr/bin/env node
// Reset the ops.chinmoy.site dashboard credentials.
// Usage:  node reset-password.mjs '<password>' [username]
// Keeps the session secret, so existing logins stay valid.
import { readFile, writeFile, chmod } from 'node:fs/promises';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const AUTH_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'auth.json');
const pw = process.argv[2];
const user = process.argv[3];

if (!pw) {
  console.error("Usage: node reset-password.mjs '<password>' [username]");
  process.exit(1);
}
if (pw.length < 8) console.warn('⚠️  Short password — fine for testing, risky on a public URL.');

let cfg = {};
try { cfg = JSON.parse(await readFile(AUTH_FILE, 'utf8')); } catch {}

cfg.secret ??= crypto.randomBytes(32).toString('hex');
if (user) cfg.user = user;
cfg.user ??= 'crimxnhaze';
cfg.salt = crypto.randomBytes(16).toString('hex');
cfg.hash = crypto.scryptSync(pw, Buffer.from(cfg.salt, 'hex'), 64).toString('hex');

await writeFile(AUTH_FILE, JSON.stringify(cfg, null, 2));
await chmod(AUTH_FILE, 0o600);
console.log(`Credentials updated for user "${cfg.user}".`);
