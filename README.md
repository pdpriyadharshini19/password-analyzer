# Password Strength Analyzer

A dependency-free Python CLI that scores passwords, suggests stronger ones, and
blocks password reuse with a salted-hash history. Built to learn password
security and basic cryptography.

## Features
- **Analyze**: length, complexity and uniqueness checks, entropy estimate, offline/online crack-time estimates
- **Pattern detection**: dictionary words (with leetspeak), keyboard walks, sequences, repeats, years, common passwords
- **Suggest**: random passwords and passphrases generated with `secrets`
- **Reuse prevention**: SQLite history of salted PBKDF2-HMAC-SHA256 hashes (plaintext is never stored)
- **Demo**: hashing, salting, key stretching and entropy side by side

## Quick start
```bash
git clone https://github.com/pdpriyadharshini19/password-analyzer.git
cd password-analyzer
python password_analyzer.py analyze
python password_analyzer.py suggest --count 3
python password_analyzer.py set-password alice
python password_analyzer.py history alice
python password_analyzer.py demo
```
Requires Python 3.9+. Run the tests with `pip install pytest && pytest`.

## Web version
`index.html` is a single-file web version with the same features: live strength analysis, password and passphrase suggestions (`crypto.getRandomValues`), and a reuse check that stores salted PBKDF2-SHA256 hashes in the browser's localStorage.

- Live demo: https://pdpriyadharshini19.github.io/password-analyzer/
- Run locally: double-click `index.html`.

Everything runs in the browser and nothing is sent to a server.

## Cryptography concepts
| Concept | Where |
|---|---|
| Entropy (bits = length x log2(pool)) | `analyze()` |
| One-way hashing | `hash_password()` |
| Per-password salt | `secrets.token_bytes(16)` in `hash_password()` |
| Key stretching (600,000 PBKDF2 iterations) | `ITERATIONS` |
| CSPRNG vs `random` | `gen_password()`, `gen_passphrase()` |
| Constant-time comparison | `hmac.compare_digest` in `verify_password()` |

## Limitations
- Built-in word lists are small, so uncommon words are scored as random characters. Use a large breached-password list or zxcvbn for production.
- The built-in passphrase list gives about 8 bits per word; pass the EFF list via `--wordlist` for about 12.9 bits.
- Avoid `--password` on shared machines (shell history). Omit it to be prompted with hidden input.
- Educational project, not a drop-in authentication system.

## License
MIT
