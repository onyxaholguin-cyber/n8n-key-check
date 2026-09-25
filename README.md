# n8n-key-check

**Does this `N8N_ENCRYPTION_KEY` actually decrypt my n8n credentials?** Find out *before* you migrate servers, restore a backup or rebuild a container, not after every credential shows "Credentials could not be decrypted".

```
$ N8N_ENCRYPTION_KEY=... npx github:onyxaholguin-cyber/n8n-key-check creds.json
MATCH    N8N_ENCRYPTION_KEY  a1b…9f (48 chars)  decrypts 8/8

OK: N8N_ENCRYPTION_KEY decrypts all 8 encrypted credential(s). Keep it with your backups.
```

- Works on a credentials **export**, a **backup folder**, or the **`database.sqlite`** file itself (read-only).
- **Found an old `.env` or config file but not sure which key is right?** `--keys` tries every candidate and tells you which one matches.
- **Never prints anything decrypted.** Keys are shown masked. Zero dependencies, about 150 lines you can read in 5 minutes.
- Exit codes for scripts and CI: `0` a key decrypts everything, `1` no key does, `2` usage error.

Tested against **n8n 2.40.6** (official Docker image): exports, `--backup` folders and the live SQLite database. It rejects a wrong key, and nothing secret appears in the output (see [test/](test/)). The format is the one n8n has used since 1.0, so older versions should work too.

## Usage

```bash
# 1. Get your credentials (encrypted, the default)
n8n export:credentials --all --output=creds.json          # or: docker compose exec n8n n8n export:credentials --all --output=/tmp/creds.json
# 2. Check the key you plan to use on the new server
N8N_ENCRYPTION_KEY='your-key' npx github:onyxaholguin-cyber/n8n-key-check creds.json
```

Other inputs:

```bash
n8n-key-check backup-dir/                    # from: n8n export:credentials --backup --output=backup-dir/
n8n-key-check ~/.n8n/database.sqlite         # SQLite, read-only. Needs Node 22.5+ (node:sqlite)
n8n-key-check creds.json --keys old.env      # try every key in a file: .env (N8N_ENCRYPTION_KEY=...), n8n config file, or one per line
n8n-key-check creds.json --keys ~/.n8n/config
n8n-key-check creds.json --json              # machine-readable
```

**SQLite tip:** copy `database.sqlite` together with `database.sqlite-wal` (or stop n8n first). Otherwise the newest credentials may still sit in the WAL file and won't be checked.

## Where is my key?

| Setup | Where n8n keeps it |
|---|---|
| `N8N_ENCRYPTION_KEY` set (recommended) | your `.env` / compose file / secret store |
| Not set | n8n generated one on first start: `~/.n8n/config` (in Docker: `/home/node/.n8n/config` inside the n8n volume) |

If you never set `N8N_ENCRYPTION_KEY`, **the key only exists inside that volume.** Lose the volume and every credential is lost with it. Copy it somewhere safe now and set it explicitly.

## How it works

n8n stores each credential as `base64("Salted__" + salt + AES-256-CBC ciphertext)`, with the key and IV derived from your encryption key (OpenSSL `EVP_BytesToKey`, MD5). You can reproduce a check with OpenSSL:

```bash
echo 'U2FsdGVkX1...' | openssl enc -d -aes-256-cbc -md md5 -a -A -pass pass:"$N8N_ENCRYPTION_KEY"
```

A value only counts as decrypted if the padding is valid **and** the result parses as JSON, so a wrong key can't pass by luck. Values in the newer key-rotation format (`<keyId>:<ciphertext>`) are reported as skipped, because they need a data key stored inside n8n.

## Related (free)

- [Back up n8n properly, including the encryption key](https://onyxaholguin-cyber.github.io/sheet-and-flow/tutorials/backup-n8n-properly/)
- [n8n-workflow-audit](https://github.com/onyxaholguin-cyber/n8n-workflow-audit): lint exported workflows for pasted secrets, open webhooks and missing error handling
- [Self-host n8n with Docker Compose + Postgres](https://onyxaholguin-cyber.github.io/sheet-and-flow/tutorials/self-host-n8n-docker-compose-postgres/)

Want this done for you? The paid **n8n Production Self-Hosting Kit** includes encrypted backups with the key handled correctly and a scripted **restore drill** that runs this kind of check. It's listed [on the site](https://onyxaholguin-cyber.github.io/sheet-and-flow/#products). This tool is free and MIT-licensed either way.

*Not affiliated with n8n GmbH. "n8n" is a trademark of n8n GmbH.*
