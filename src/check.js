'use strict';
// Checks whether an n8n encryption key can decrypt n8n credentials, without printing any secret.
// n8n's default credential format (1.x and 2.x): base64("Salted__" + 8-byte salt + AES-256-CBC ciphertext),
// key and IV derived with OpenSSL's EVP_BytesToKey (MD5, 1 round), the same scheme as `openssl enc -aes-256-cbc -md md5`.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAGIC = Buffer.from('Salted__', 'latin1');
const KEY_ID = /^([A-Za-z0-9_-]{1,36}):(.+)$/s;

function deriveKeyIv(key, salt) {
  const pass = Buffer.concat([Buffer.from(String(key), 'latin1'), salt]);
  const h1 = crypto.createHash('md5').update(pass).digest();
  const h2 = crypto.createHash('md5').update(Buffer.concat([h1, pass])).digest();
  const iv = crypto.createHash('md5').update(Buffer.concat([h2, pass])).digest();
  return { key: Buffer.concat([h1, h2]), iv };
}

function encrypt(plaintext, key, salt = crypto.randomBytes(8)) {
  const k = deriveKeyIv(key, salt);
  const c = crypto.createCipheriv('aes-256-cbc', k.key, k.iv);
  return Buffer.concat([MAGIC, salt, c.update(plaintext, 'utf8'), c.final()]).toString('base64');
}

// Classify a stored credential value.
function format(data) {
  if (data && typeof data === 'object') return 'plaintext-object';          // export made with --decrypted
  const s = String(data || '');
  if (s.startsWith('U2FsdGVkX1')) return 'salted-aes-256-cbc';              // base64 of "Salted__"
  const m = KEY_ID.exec(s);
  if (m && m[2].length >= 16) return 'key-id-prefixed';                     // newer key-rotation format: <keyId>:<ciphertext>
  return 'unknown';
}

// Returns { ok, reason }. Never returns the decrypted content.
function tryDecrypt(data, key) {
  const f = format(data);
  if (f === 'plaintext-object') return { ok: null, reason: 'not encrypted (export was made with --decrypted)' };
  if (f === 'key-id-prefixed') return { ok: null, reason: 'encrypted with a rotated data key (keyId:... format); check it inside n8n instead' };
  if (f !== 'salted-aes-256-cbc') return { ok: null, reason: 'not an n8n encrypted value' };
  const buf = Buffer.from(String(data), 'base64');
  if (buf.length < 32 || !buf.subarray(0, 8).equals(MAGIC)) return { ok: false, reason: 'corrupt ciphertext' };
  const k = deriveKeyIv(key, buf.subarray(8, 16));
  try {
    const d = crypto.createDecipheriv('aes-256-cbc', k.key, k.iv);
    const out = Buffer.concat([d.update(buf.subarray(16)), d.final()]).toString('utf8');
    JSON.parse(out);                       // n8n stores credential data as JSON; a wrong key almost never yields valid padding AND valid JSON
    return { ok: true, reason: 'decrypts' };
  } catch (e) {
    return { ok: false, reason: 'wrong key (does not decrypt)' };
  }
}

// Accepts: an array export (`n8n export:credentials --all --output=file.json`), a single credential object,
// a directory of per-credential files (`--backup --output=dir/`), or an n8n SQLite database (Node 22.5+ has node:sqlite).
function loadCredentials(p) {
  const st = fs.statSync(p);
  if (st.isDirectory()) return fs.readdirSync(p).filter(f => f.endsWith('.json')).sort().flatMap(f => loadCredentials(path.join(p, f)));
  const head = fs.readFileSync(p).subarray(0, 16).toString('latin1');
  if (head.startsWith('SQLite format 3')) return loadSqlite(p);
  const j = JSON.parse(fs.readFileSync(p, 'utf8'));
  const arr = Array.isArray(j) ? j : [j];
  return arr.filter(c => c && 'data' in c).map(c => ({ id: c.id || '', name: c.name || '(unnamed)', type: c.type || '', data: c.data, source: p }));
}

function loadSqlite(p) {
  let sqlite;
  try { sqlite = require('node:sqlite'); } catch (e) {
    throw new Error('Reading a SQLite database needs Node.js 22.5 or newer (node:sqlite). Or export first: n8n export:credentials --all --output=creds.json');
  }
  const db = new sqlite.DatabaseSync(p, { readOnly: true });
  try {
    const t = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%credentials_entity'").all();
    if (!t.length) throw new Error('no credentials_entity table in ' + p);
    return db.prepare(`SELECT id, name, type, data FROM "${t[0].name}"`).all().map(r => ({ ...r, source: p }));
  } finally { db.close(); }
}

// Read candidate keys: n8n config file ({"encryptionKey": ...}), a .env file (N8N_ENCRYPTION_KEY=...), or a plain list (one per line).
function loadKeys(p) {
  const txt = fs.readFileSync(p, 'utf8');
  try { const j = JSON.parse(txt); if (j && typeof j.encryptionKey === 'string') return [{ key: j.encryptionKey, label: p + ' (encryptionKey)' }]; } catch (e) { /* not JSON */ }
  const keys = [];
  txt.split(/\r?\n/).forEach((line, i) => {
    const l = line.trim();
    if (!l || l.startsWith('#')) return;
    const m = /^(?:export\s+)?N8N_ENCRYPTION_KEY\s*=\s*(.*)$/.exec(l);
    if (m) keys.push({ key: m[1].trim().replace(/^(['"])(.*)\1$/, '$2'), label: `${p}:${i + 1} (N8N_ENCRYPTION_KEY)` });
    else if (!/^[A-Z_][A-Z0-9_]*\s*=/.test(l)) keys.push({ key: l, label: `${p}:${i + 1}` });
  });
  return keys;
}

function mask(k) {
  const s = String(k);
  if (s.length <= 8) return '*'.repeat(s.length);
  return s.slice(0, 3) + '…' + s.slice(-2) + ` (${s.length} chars)`;
}

function check(creds, keys) {
  const results = keys.map(k => {
    const per = creds.map(c => ({ name: c.name, type: c.type, id: c.id, ...tryDecrypt(c.data, k.key) }));
    const tested = per.filter(r => r.ok !== null);
    return { label: k.label, masked: mask(k.key), ok: tested.filter(r => r.ok).length, failed: tested.filter(r => r.ok === false).length, skipped: per.length - tested.length, per };
  });
  return results;
}

module.exports = { deriveKeyIv, encrypt, format, tryDecrypt, loadCredentials, loadKeys, mask, check };
