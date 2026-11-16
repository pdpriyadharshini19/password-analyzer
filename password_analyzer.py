#!/usr/bin/env python3
"""
Password Strength Analyzer  (standard library only, Python 3.8+)

What it does
  1. analyze      - checks length, complexity and uniqueness, estimates entropy and crack time
  2. suggest      - generates stronger passwords / passphrases with a CSPRNG
  3. set-password - policy check + salted-hash history so old passwords can't be reused
  4. demo         - shows hashing, salting and key stretching side by side

Crypto ideas you will meet (each is marked "CRYPTO:" in the code)
  - entropy        : how many guesses an attacker needs, measured in bits
  - hashing        : one-way function, so the database never holds the password
  - salt           : random per-password value so equal passwords hash differently
  - key stretching : PBKDF2 repeats the hash many times to slow brute force
  - CSPRNG         : `secrets` (not `random`) for anything security related
  - constant-time  : hmac.compare_digest so comparisons don't leak timing

Usage
  python password_analyzer.py analyze
  python password_analyzer.py suggest --count 3
  python password_analyzer.py set-password alice
  python password_analyzer.py history alice
  python password_analyzer.py demo
"""
import argparse
import getpass
import hashlib
import hmac
import itertools
import math
import re
import secrets
import sqlite3
import string
import sys
import time
from datetime import datetime, timezone

# ----------------------------------------------------------------------------
# Data
# ----------------------------------------------------------------------------
COMMON = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123", "password1",
    "111111", "iloveyou", "admin", "welcome", "letmein", "monkey", "dragon", "football",
    "baseball", "master", "login", "sunshine", "princess", "qwerty123", "1q2w3e4r",
    "passw0rd", "admin123", "000000", "123123", "zaq12wsx", "trustno1", "superman", "batman",
}
WORDS = {
    "password", "passwd", "admin", "welcome", "letmein", "monkey", "dragon", "master", "login",
    "iloveyou", "sunshine", "princess", "football", "baseball", "secret", "hello", "india",
    "chennai", "student", "college", "engineer", "computer", "summer", "winter", "love",
    "qwerty", "user", "test", "guest", "family", "shadow", "cricket", "tamil", "freedom",
    "internet",
}
LEET = {"4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "0": "o", "5": "s", "$": "s", "7": "t", "8": "b"}
KEY_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
LEVELS = ["Very weak", "Weak", "Fair", "Strong", "Excellent"]

# Passphrase word list (about 8 bits per word). For real use, pass --wordlist with
# the EFF large list (7,776 words = 12.9 bits per word).
PASSPHRASE_WORDS = sorted(set("""
acorn alpine anchor apple arrow autumn badge bamboo banner barrel basket beacon beetle berry
bicycle biscuit blanket bottle bridge bronze bubble butter cabin cactus camera candle canyon
carpet carrot castle cedar chalk cherry circus cinder cliff clover cloud cobalt coconut comet
compass cookie copper coral cotton cradle crane crystal curtain daffodil daisy delta desert
diamond dinner dolphin drum dune eagle elbow emerald ember engine fabric falcon feather ferry
fiddle flame flint forest fountain frost gadget galaxy garden ginger glacier goblet granite
gravel guitar hammer harbor harvest hazel helmet hollow honey iceberg island jacket jigsaw
jungle kernel kettle kingdom kitten ladder lagoon lantern lemon lemonade library lizard locket
lotus magnet mammoth mango maple marble meadow melody mirror monsoon mosaic mountain mustard
nebula needle nickel noodle nutmeg oasis ocean olive orange orchid otter oyster paddle paprika
parrot peanut pearl pebble pepper pigeon pillow pirate planet plume pocket poncho pretzel prism
pudding pumpkin puzzle quartz quill rabbit radish raven ribbon river rocket saddle saffron
sailor salmon sandal sketch slate sparrow spice spider spruce squirrel stable sundial sunset
swallow tablet teapot temple thistle thunder tiger timber tomato trumpet tulip tunnel turtle
umbrella valley vanilla velvet violin vortex waffle wagon walnut walrus whisper willow window
wizard yarn yogurt zebra zephyr
""".split()))

# ----------------------------------------------------------------------------
# 1. Strength analysis
# ----------------------------------------------------------------------------
def char_kind(c):
    if c.islower():
        return "lower"
    if c.isupper():
        return "upper"
    if c.isdigit():
        return "digit"
    return "symbol"


def analyze(pw):
    """Return a dict describing the password's strength."""
    chars = list(pw)
    n = len(chars)
    low = [c.lower() for c in chars]
    low_s = "".join(low)
    norm_s = "".join(LEET.get(c, c) for c in low)     # undo p@ssw0rd style swaps
    used = [None] * n                                 # which pattern covers each index
    findings = []

    def add(start, length, label, bits):
        if any(used[start + k] for k in range(length)):
            return                                    # don't double count a character
        seg = (start, length, label, bits)
        for k in range(length):
            used[start + k] = seg
        findings.append(seg)

    # Patterns an attacker tries first. Each is charged a small fixed number of bits.
    for m in re.finditer(r"(?:19|20)\d{2}", pw):
        add(m.start(), 4, "a year", 7)
    for w in WORDS:
        for m in re.finditer(re.escape(w), norm_s):
            leet = low_s[m.start():m.end()] != w
            add(m.start(), len(w), f'the word "{w}"' + (" (with substitutions)" if leet else ""),
                12 if leet else 10)
    for row in KEY_ROWS + [r[::-1] for r in KEY_ROWS]:
        for size in range(min(10, len(row)), 3, -1):
            for a in range(len(row) - size + 1):
                sub = row[a:a + size]
                for m in re.finditer(re.escape(sub), low_s):
                    add(m.start(), size, "a keyboard pattern", 6)
    i = 0
    while i < n - 2:                                  # sequences like abc or 321
        d = ord(low[i + 1]) - ord(low[i])
        if abs(d) == 1:
            j = i + 1
            while j + 1 < n and ord(low[j + 1]) - ord(low[j]) == d:
                j += 1
            if j - i + 1 >= 3:
                add(i, j - i + 1, "a sequence", 5)
                i = j
                continue
        i += 1
    pos = 0
    for _, grp in itertools.groupby(low):             # repeats like aaa
        size = len(list(grp))
        if size >= 3:
            add(pos, size, "a repeated character", 3)
        pos += size

    # CRYPTO: entropy. A random character from a pool of size P adds log2(P) bits.
    kinds = {char_kind(c) for c in chars}
    pool = (26 * ("lower" in kinds) + 26 * ("upper" in kinds)
            + 10 * ("digit" in kinds) + 33 * ("symbol" in kinds))
    free = sum(1 for u in used if u is None)
    bits = sum(f[3] for f in findings) + (free * math.log2(pool) if pool else 0)

    is_common = low_s in COMMON or norm_s in COMMON
    if is_common:
        bits = min(bits, 8)

    score = 0 if bits < 28 else 1 if bits < 36 else 2 if bits < 60 else 3 if bits < 80 else 4
    checks = {
        "At least 12 characters": n >= 12,
        "Mixes upper and lower case": "lower" in kinds and "upper" in kinds,
        "Includes a digit": "digit" in kinds,
        "Includes a symbol": "symbol" in kinds,
        "Not a commonly used password": not is_common,
        "No words, sequences or repeats": not findings,
    }
    return {"length": n, "bits": bits, "score": score, "label": LEVELS[score],
            "findings": sorted(findings), "checks": checks, "common": is_common}


def crack_time(bits, rate):
    """Average time to guess = half the search space / guesses per second."""
    seconds = (2 ** bits) / 2 / rate
    if seconds < 1:
        return "instantly"
    for name, size in (("seconds", 60), ("minutes", 60), ("hours", 24), ("days", 365)):
        if seconds < size:
            count = round(seconds)
            return f"{count} {name if count != 1 else name[:-1]}"
        seconds /= size
    if seconds < 1e3:
        return f"{seconds:.0f} years"
    if seconds < 1e6:
        return f"{seconds / 1e3:.0f} thousand years"
    if seconds < 1e9:
        return f"{seconds / 1e6:.1f} million years"
    return f"{seconds / 1e9:.1f} billion years" if seconds < 1e12 else "trillions of years"


def print_report(r):
    print(f"\nStrength : {r['label']}  ({r['score'] + 1}/5)")
    print(f"Length   : {r['length']} characters")
    print(f"Entropy  : ~{r['bits']:.0f} bits")
    print(f"Offline  : {crack_time(r['bits'], 1e10)}   (10 billion guesses/s, fast hash)")
    print(f"Online   : {crack_time(r['bits'], 100)}   (100 guesses/s, rate limited)\n")
    for name, ok in r["checks"].items():
        print(f"  [{'x' if ok else ' '}] {name}")
    if r["common"]:
        print("\n  ! This is one of the most common passwords; attackers try it first.")
    for start, length, label, _ in r["findings"]:
        print(f"  ! Characters {start + 1}-{start + length} are {label}.")

# ----------------------------------------------------------------------------
# 2. Suggestions
# ----------------------------------------------------------------------------
def gen_password(length=16):
    """Random characters. CRYPTO: `secrets` draws from the OS CSPRNG; `random` is predictable."""
    alphabet = string.ascii_letters + string.digits + SYMBOLS
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in SYMBOLS for c in pw)):
            return pw, length * math.log2(len(alphabet))


def gen_passphrase(words=6, wordlist=None):
    """Random words + digits + symbol: easier to remember, entropy counted honestly."""
    wl = wordlist or PASSPHRASE_WORDS
    parts = [secrets.choice(wl) for _ in range(words)]
    number = "".join(secrets.choice(string.digits) for _ in range(3))
    symbol = secrets.choice(SYMBOLS)
    bits = words * math.log2(len(wl)) + 3 * math.log2(10) + math.log2(len(SYMBOLS))
    return "-".join(parts) + symbol + number, bits

# ----------------------------------------------------------------------------
# 3. Salted-hash storage and reuse prevention
# ----------------------------------------------------------------------------
ITERATIONS = 600_000        # OWASP 2023 minimum for PBKDF2-HMAC-SHA256


def hash_password(pw, salt=None, iterations=ITERATIONS):
    # CRYPTO: salt = 16 random bytes, stored next to the hash (it is not secret).
    # CRYPTO: PBKDF2 repeats HMAC-SHA256 `iterations` times (key stretching).
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(pw, stored):
    _, iters, salt_hex, digest_hex = stored.split("$")
    candidate = hash_password(pw, bytes.fromhex(salt_hex), int(iters))
    # CRYPTO: constant-time comparison so response time doesn't leak matching bytes.
    return hmac.compare_digest(candidate.split("$")[3], digest_hex)


class PasswordVault:
    """SQLite table of previous password hashes. Plaintext is never stored."""

    def __init__(self, path="password_history.db"):
        self.db = sqlite3.connect(path)
        self.db.execute("""CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            hash TEXT NOT NULL,
            created_at TEXT NOT NULL)""")

    def recent(self, user, limit):
        rows = self.db.execute(
            "SELECT hash, created_at FROM password_history WHERE username=? "
            "ORDER BY id DESC LIMIT ?", (user, limit)).fetchall()
        return rows

    def was_used(self, user, pw, limit=5):
        # Each old hash has its own salt, so we must re-hash once per entry.
        return any(verify_password(pw, h) for h, _ in self.recent(user, limit))

    def save(self, user, pw):
        self.db.execute("INSERT INTO password_history (username, hash, created_at) VALUES (?,?,?)",
                        (user, hash_password(pw), datetime.now(timezone.utc).isoformat(timespec="seconds")))
        self.db.commit()

# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def ask(prompt="Password: "):
    return getpass.getpass(prompt)       # hidden input, not stored in shell history


def cmd_analyze(a):
    print_report(analyze(a.password or ask()))


def cmd_suggest(a):
    wl = None
    if a.wordlist:
        with open(a.wordlist, encoding="utf-8") as f:
            wl = [w.split()[-1] for w in f if w.strip()]     # supports EFF "11111 word" format
    print("\nRandom passwords")
    for _ in range(a.count):
        pw, bits = gen_password(a.length)
        print(f"  {pw}   (~{bits:.0f} bits)")
    print("\nPassphrases")
    for _ in range(a.count):
        pw, bits = gen_passphrase(a.words, wl)
        print(f"  {pw}   (~{bits:.0f} bits)")
    print("\nStore generated passwords in a password manager and use each one on a single site.")


def cmd_set(a):
    vault = PasswordVault(a.db)
    pw = a.password or ask("New password: ")
    r = analyze(pw)
    print_report(r)
    problems = []
    if r["score"] < a.min_score:
        problems.append(f"strength is {r['label']}, policy requires {LEVELS[a.min_score]} or better")
    if r["length"] < 12:
        problems.append("shorter than 12 characters")
    if vault.was_used(a.user, pw, a.history):
        problems.append(f"matches one of the last {a.history} passwords for this user")
    if problems:
        print("\nRejected:")
        for p in problems:
            print(f"  - {p}")
        sug, bits = gen_passphrase()
        print(f"\nTry something like: {sug}   (~{bits:.0f} bits)")
        sys.exit(1)
    vault.save(a.user, pw)
    print(f"\nAccepted. Salted PBKDF2 hash stored for '{a.user}'.")


def cmd_history(a):
    for h, ts in PasswordVault(a.db).recent(a.user, 20):
        algo, iters, salt, digest = h.split("$")
        print(f"{ts}  {algo} x{iters}  salt={salt[:8]}...  hash={digest[:16]}...")


def cmd_demo(_):
    pw = "Tr0ub4dor&3"
    print("1) Plain SHA-256 has no salt, so equal passwords give equal hashes:")
    print("  ", hashlib.sha256(pw.encode()).hexdigest()[:32], "...")
    print("  ", hashlib.sha256(pw.encode()).hexdigest()[:32], "...  (identical)")
    print("\n2) Add a random salt per user, and the same password differs:")
    for _ in range(2):
        print("  ", hash_password(pw, iterations=1000).split("$")[3][:32], "...")
    print("\n3) Key stretching makes every guess cost more:")
    for iters in (1, 100_000, ITERATIONS):
        t = time.perf_counter()
        hashlib.pbkdf2_hmac("sha256", pw.encode(), b"saltsalt", iters)
        dt = time.perf_counter() - t
        print(f"   {iters:>8,} iterations: {dt * 1000:8.1f} ms per guess")
    print("\n4) Entropy: a guess costs the attacker 2^bits tries.")
    for label, bits in (("8 random lowercase letters", 8 * math.log2(26)),
                        ("12 random mixed characters", 12 * math.log2(94)),
                        ("6 random words (this list)", 6 * math.log2(len(PASSPHRASE_WORDS)))):
        print(f"   {label:<28} ~{bits:.0f} bits  ->  {crack_time(bits, 1e10)} offline")


def main():
    p = argparse.ArgumentParser(description="Password strength analyzer")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("analyze", help="score a password")
    s.add_argument("--password", help="avoid this: it lands in shell history; omit to be prompted")
    s.set_defaults(fn=cmd_analyze)

    s = sub.add_parser("suggest", help="generate stronger passwords")
    s.add_argument("--count", type=int, default=3)
    s.add_argument("--length", type=int, default=16)
    s.add_argument("--words", type=int, default=6)
    s.add_argument("--wordlist", help="file with one word per line (EFF diceware works)")
    s.set_defaults(fn=cmd_suggest)

    s = sub.add_parser("set-password", help="validate and store a new password for a user")
    s.add_argument("user")
    s.add_argument("--password")
    s.add_argument("--db", default="password_history.db")
    s.add_argument("--history", type=int, default=5, help="how many old passwords to block")
    s.add_argument("--min-score", type=int, default=3, choices=range(5))
    s.set_defaults(fn=cmd_set)

    s = sub.add_parser("history", help="show stored hash records for a user")
    s.add_argument("user")
    s.add_argument("--db", default="password_history.db")
    s.set_defaults(fn=cmd_history)

    s = sub.add_parser("demo", help="hashing, salting and entropy walkthrough")
    s.set_defaults(fn=cmd_demo)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
