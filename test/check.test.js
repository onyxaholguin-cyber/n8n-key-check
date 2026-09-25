'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs'); const os = require('os'); const path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const K = require('../src/check.js');
const FX = path.join(__dirname, 'fixtures'); const EXPORT = path.join(FX, 'n8n-2.40.6-export.json');
const KEY = 'fixture-key-NOT-a-secret-0123456789';
const BIN = path.join(__dirname, '..', 'bin', 'n8n-key-check.js');
const run = (args, env = {}) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', env: { ...process.env, N8N_ENCRYPTION_KEY: '', ...env } });

test('decrypts values produced by the real n8n 2.40.6 cipher', () => {
  const creds = K.loadCredentials(EXPORT);
  assert.strictEqual(creds.length, 3);
  for (const c of creds) assert.deepStrictEqual(K.tryDecrypt(c.data, KEY), { ok: true, reason: 'decrypts' });
});
test('wrong key is rejected for every credential', () => {
  for (const c of K.loadCredentials(EXPORT)) assert.strictEqual(K.tryDecrypt(c.data, KEY + 'x').ok, false);
});
test('round trip with our encrypt (openssl-compatible)', () => {
  const v = K.encrypt(JSON.stringify({ a: 1 }), 'k');
  assert.ok(v.startsWith('U2FsdGVkX1'));
  assert.strictEqual(K.tryDecrypt(v, 'k').ok, true);
});
test('non-JSON plaintext counts as failure (guards against lucky padding)', () => {
  assert.strictEqual(K.tryDecrypt(K.encrypt('not json', 'k'), 'k').ok, false);
});
test('formats: decrypted export, key-id prefixed, garbage', () => {
  assert.strictEqual(K.tryDecrypt({ user: 'x' }, KEY).ok, null);
  assert.strictEqual(K.format('abc123:' + 'A'.repeat(40)), 'key-id-prefixed');
  assert.strictEqual(K.tryDecrypt('abc123:' + 'A'.repeat(40), KEY).ok, null);
  assert.strictEqual(K.tryDecrypt('hello', KEY).ok, null);
  assert.strictEqual(K.tryDecrypt('U2FsdGVkX1' + 'A', KEY).ok, false);
});
test('keys from config file, .env line and plain list', () => {
  assert.deepStrictEqual(K.loadKeys(path.join(FX, 'config')).map(k => k.key), [KEY]);
  assert.deepStrictEqual(K.loadKeys(path.join(FX, 'keys.txt')).map(k => k.key), ['old-laptop-key-not-it', KEY]);
});
test('mask never reveals the key', () => {
  const m = K.mask(KEY);
  assert.ok(!m.includes('NOT-a-secret')); assert.ok(m.includes('35 chars'));
  assert.strictEqual(K.mask('short'), '*****');
});
test('backup directory (one file per credential)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kc-'));
  JSON.parse(fs.readFileSync(EXPORT, 'utf8')).forEach((c, i) => fs.writeFileSync(path.join(dir, `${i}.json`), JSON.stringify(c)));
  assert.strictEqual(K.loadCredentials(dir).length, 3);
});
test('CLI: env key matches -> exit 0, nothing secret printed', () => {
  const r = run([EXPORT], { N8N_ENCRYPTION_KEY: KEY });
  assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /MATCH\s+N8N_ENCRYPTION_KEY/); assert.match(r.stdout, /decrypts 3\/3/);
  for (const s of [KEY, 'fixture-pass', 'fixture-not-a-token']) assert.ok(!r.stdout.includes(s), 'leaked ' + s);
});
test('CLI: wrong key -> exit 1', () => {
  const r = run([EXPORT], { N8N_ENCRYPTION_KEY: 'nope-nope-nope' });
  assert.strictEqual(r.status, 1); assert.match(r.stdout, /NO MATCH/);
});
test('CLI: --keys finds the right candidate, --json output', () => {
  const r = run([EXPORT, '--keys', path.join(FX, 'keys.txt'), '--json']);
  assert.strictEqual(r.status, 0);
  const j = JSON.parse(r.stdout);
  assert.strictEqual(j.match.length, 1); assert.match(j.match[0], /keys\.txt:3/);
  assert.ok(!r.stdout.includes(KEY));
});
test('CLI: usage errors -> exit 2', () => {
  assert.strictEqual(run([]).status, 2);
  assert.strictEqual(run([EXPORT]).status, 2);
  assert.strictEqual(run(['/nonexistent.json'], { N8N_ENCRYPTION_KEY: 'x' }).status, 2);
});
test('SQLite database (Node 22.5+ only)', { skip: (() => { try { require('node:sqlite'); return false; } catch { return 'node:sqlite not available'; } })() }, () => {
  const sqlite = require('node:sqlite');
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'kc-')), 'database.sqlite');
  const db = new sqlite.DatabaseSync(f);
  db.exec('CREATE TABLE credentials_entity (id TEXT, name TEXT, type TEXT, data TEXT)');
  const ins = db.prepare('INSERT INTO credentials_entity VALUES (?, ?, ?, ?)');
  for (const c of JSON.parse(fs.readFileSync(EXPORT, 'utf8'))) ins.run(c.id, c.name, c.type, c.data);
  db.close();
  const r = run([f], { N8N_ENCRYPTION_KEY: KEY });
  assert.strictEqual(r.status, 0, r.stdout + r.stderr); assert.match(r.stdout, /decrypts 3\/3/);
});
