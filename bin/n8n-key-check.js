#!/usr/bin/env node
'use strict';
const path = require('path');
const K = require('../src/check.js');
const HELP = `n8n-key-check: does this N8N_ENCRYPTION_KEY decrypt my n8n credentials?

Usage:
  N8N_ENCRYPTION_KEY=... n8n-key-check <credentials>
  n8n-key-check <credentials> --keys <file>   (n8n config file, .env file, or one candidate key per line)

<credentials> is one of:
  creds.json      from: n8n export:credentials --all --output=creds.json   (encrypted export, the default)
  backup-dir/     from: n8n export:credentials --backup --output=backup-dir/
  database.sqlite the n8n SQLite database (~/.n8n/database.sqlite), read-only, needs Node 22.5+

Options:
  --keys <file>   try every key in the file and report which one works
  --json          machine-readable output
  --quiet         only the summary line
Exit code: 0 = a key decrypts every encrypted credential, 1 = no key decrypts all of them, 2 = usage error.
Nothing decrypted is ever printed. Keys are shown masked.`;

function main(argv) {
  const args = argv.slice(2);
  if (!args.length || args.includes('-h') || args.includes('--help')) { console.log(HELP); return args.length ? 0 : 2; }
  const opt = { json: args.includes('--json'), quiet: args.includes('--quiet') };
  const ki = args.indexOf('--keys');
  const keysFile = ki >= 0 ? args[ki + 1] : null;
  const files = args.filter((a, i) => !a.startsWith('--') && !(ki >= 0 && i === ki + 1));
  if (!files.length) { console.error('error: pass a credentials export, backup folder or database.sqlite'); return 2; }
  let keys;
  try {
    keys = keysFile ? K.loadKeys(keysFile) : process.env.N8N_ENCRYPTION_KEY ? [{ key: process.env.N8N_ENCRYPTION_KEY, label: 'N8N_ENCRYPTION_KEY' }] : [];
  } catch (e) { console.error('error: ' + e.message); return 2; }
  if (!keys.length) { console.error('error: set N8N_ENCRYPTION_KEY or pass --keys <file>'); return 2; }
  let creds;
  try { creds = files.flatMap(f => K.loadCredentials(f)); } catch (e) { console.error('error: ' + e.message); return 2; }
  if (!creds.length) { console.error('error: no credentials found in ' + files.join(', ')); return 2; }
  const res = K.check(creds, keys);
  const winners = res.filter(r => r.ok > 0 && r.failed === 0);
  if (opt.json) {
    console.log(JSON.stringify({ credentials: creds.length, keys: res.map(r => ({ key: r.label, masked: r.masked, decrypts: r.ok, fails: r.failed, skipped: r.skipped,
      results: r.per.map(p => ({ name: p.name, type: p.type, id: p.id, ok: p.ok, reason: p.reason })) })), match: winners.map(w => w.label) }, null, 2));
    return winners.length ? 0 : 1;
  }
  for (const r of res) {
    const verdict = r.ok > 0 && r.failed === 0 ? 'MATCH' : r.ok > 0 ? 'PARTIAL' : 'NO MATCH';
    console.log(`${verdict.padEnd(8)} ${r.label}  ${r.masked}  decrypts ${r.ok}/${r.ok + r.failed}${r.skipped ? `, ${r.skipped} skipped` : ''}`);
    if (!opt.quiet && (res.length === 1 || verdict === 'PARTIAL')) {
      for (const p of r.per) console.log(`   ${p.ok === true ? '✓' : p.ok === false ? '✗' : '-'} ${p.name} [${p.type}]${p.ok === true ? '' : ': ' + p.reason}`);
    }
  }
  if (winners.length) console.log(`\nOK: ${winners[0].label} decrypts all ${winners[0].ok} encrypted credential(s). Keep it with your backups.`);
  else console.log('\nNo key decrypts every credential. Restoring with these keys would leave credentials unusable ("Credentials could not be decrypted").');
  return winners.length ? 0 : 1;
}
if (require.main === module) process.exitCode = main(process.argv);
module.exports = { main };
