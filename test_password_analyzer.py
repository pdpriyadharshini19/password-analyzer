import password_analyzer as pa


def labels(result):
    return [f[2] for f in result["findings"]]


def test_common_password_is_very_weak():
    r = pa.analyze("password")
    assert r["common"] and r["score"] == 0


def test_leetspeak_word_and_year_detected():
    r = pa.analyze("P@ssw0rd2024")
    assert any("password" in l for l in labels(r))
    assert any("year" in l for l in labels(r))


def test_sequence_and_repeat_detected():
    assert any("sequence" in l for l in labels(pa.analyze("xabcx")))
    assert any("repeated" in l for l in labels(pa.analyze("aaaa")))


def test_generated_password_is_strong_and_complete():
    pw, _ = pa.gen_password(16)
    assert len(pw) == 16
    assert any(c.islower() for c in pw) and any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw) and any(c in pa.SYMBOLS for c in pw)
    assert pa.analyze(pw)["score"] >= 3


def test_passphrase_reports_honest_entropy():
    _, bits = pa.gen_passphrase(6)
    assert bits > 50


def test_hash_is_salted_and_verifiable():
    a = pa.hash_password("hunter2!", iterations=1000)
    b = pa.hash_password("hunter2!", iterations=1000)
    assert a != b                      # different salts
    assert pa.verify_password("hunter2!", a)
    assert not pa.verify_password("Hunter2!", a)


def test_vault_blocks_reuse_per_user(tmp_path):
    v = pa.PasswordVault(str(tmp_path / "t.db"))
    v.save("alice", "S3cret-pass!")
    assert v.was_used("alice", "S3cret-pass!")
    assert not v.was_used("alice", "different")
    assert not v.was_used("bob", "S3cret-pass!")


def test_history_limit(tmp_path):
    v = pa.PasswordVault(str(tmp_path / "t.db"))
    for pw in ("one-pass", "two-pass", "three-pass"):
        v.save("alice", pw)
    assert v.was_used("alice", "three-pass", limit=2)
    assert not v.was_used("alice", "one-pass", limit=2)   # fell out of the window
