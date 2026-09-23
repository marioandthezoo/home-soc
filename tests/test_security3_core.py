"""Third security round, core fixes: each test encodes one reproduced race.

1. ``lens_consume_pairing_code`` read the pairing rows, compared, then deleted in separate lock
   acquisitions and never checked the DELETE's row count, so two ``/api/lens/claim`` requests
   landing together both spent ONE code and both got a token (reproduced: 2, then 3 tokens).
2. ``lens_mint_token`` counted active tokens and inserted in separate lock acquisitions, so the
   same burst went past ``lens.max_tokens`` (reproduced: 15 of 10 active).
3. ``lens_claim_attempt`` was an unlocked read-modify-write: a burst of 100 simultaneous wrong
   codes was checked in full against a limit of 10, and a late writer could erase a lockout.

The races are made deterministic by widening the read-to-write gap with a short sleep inside the
helpers the old code read through; with the fix, that gap sits inside the write lock and the
threads simply queue.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable

import pytest

from homesoc import db

GAP = 0.05  # seconds the read-to-write window is held open for each thread


def _burst(n: int, fn: Callable[[int], Any]) -> list[Any]:
    """Run ``fn(i)`` on ``n`` threads released together; returns results in thread order."""
    barrier = threading.Barrier(n)
    results: list[Any] = [None] * n
    errors: list[BaseException] = []

    def run(i: int) -> None:
        barrier.wait()
        try:
            results[i] = fn(i)
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)
            results[i] = exc

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not any(t.is_alive() for t in threads), "a worker hung (lock not released?)"
    return results


def _slow(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Make ``db.<name>`` sleep after reading, holding a race window open."""
    real = getattr(db, name)

    def slowed(*args: Any, **kwargs: Any) -> Any:
        out = real(*args, **kwargs)
        time.sleep(GAP)
        return out

    monkeypatch.setattr(db, name, slowed)


# --------------------------------------------------------------------- 1. single-use pairing code


def test_one_pairing_code_is_spent_once_under_a_burst(conn: sqlite3.Connection, monkeypatch) -> None:
    code = db.lens_new_pairing_code(conn)
    _slow(monkeypatch, "settings_with_prefix")  # old code: every thread read the row, then deleted
    results = _burst(8, lambda i: db.lens_consume_pairing_code(conn, code))
    assert results.count(True) == 1, results
    assert db.lens_consume_pairing_code(conn, code) is False


def test_pair_with_code_mints_exactly_one_token_per_code(conn: sqlite3.Connection, monkeypatch) -> None:
    code = db.lens_new_pairing_code(conn)
    _slow(monkeypatch, "settings_with_prefix")

    def claim(i: int) -> Any:
        try:
            return db.lens_pair_with_code(conn, code, label=f"phone {i}", max_tokens=10)
        except db.LensError:
            return None

    results = _burst(8, claim)
    assert sum(1 for r in results if isinstance(r, dict) and r.get("token")) == 1, results
    assert len(db.lens_active_tokens(conn)) == 1


def test_expired_code_is_refused_and_removed(conn: sqlite3.Connection) -> None:
    code = db.lens_new_pairing_code(conn, ttl_seconds=1)
    key = next(iter(db.settings_with_prefix(conn, "lens.pairing.")))
    db.set_setting(conn, key, {"created_at": "2000-01-01T00:00:00Z", "expires_at": "2000-01-01T00:05:00Z"})
    assert db.lens_consume_pairing_code(conn, code) is False
    assert db.settings_with_prefix(conn, "lens.pairing.") == {}


def test_code_is_single_use_across_two_connections(data_dir: Path) -> None:
    """The CLI (`lens pair`) and the server hold separate connections: the DELETE decides."""
    first = db.connect()
    second = db.connect()
    try:
        code = db.lens_new_pairing_code(first)
        assert db.lens_consume_pairing_code(second, code) is True
        assert db.lens_consume_pairing_code(first, code) is False
    finally:
        first.close()
        second.close()


# --------------------------------------------------------------------------- 2. token ceiling


def test_token_ceiling_holds_under_a_burst(conn: sqlite3.Connection, monkeypatch) -> None:
    for i in range(9):
        db.lens_mint_token(conn, label=f"existing {i}", max_tokens=10)
    _slow(monkeypatch, "lens_active_tokens")  # old code: count, sleep, then INSERT

    def mint(i: int) -> Any:
        try:
            return db.lens_mint_token(conn, label=f"racer {i}", max_tokens=10)
        except db.LensTokenLimit:
            return None

    results = _burst(10, mint)
    assert sum(1 for r in results if isinstance(r, dict)) == 1, results
    assert len(db.lens_active_tokens(conn)) == 10


def test_ceiling_refusal_keeps_the_owners_code(conn: sqlite3.Connection) -> None:
    db.lens_mint_token(conn, label="only phone", max_tokens=1)
    code = db.lens_new_pairing_code(conn)
    with pytest.raises(db.LensTokenLimit):
        db.lens_pair_with_code(conn, code, label="second", max_tokens=1)
    assert db.lens_consume_pairing_code(conn, code) is True, "a refusal at the ceiling must not burn the code"


def test_wrong_code_wording_stays_plain(conn: sqlite3.Connection) -> None:
    db.lens_new_pairing_code(conn)
    with pytest.raises(db.LensError) as err:
        db.lens_pair_with_code(conn, "WRONGCOD", label="phone")
    assert "wrong, already used, or has expired" in str(err.value)


def test_mint_still_strips_control_characters_and_counts_revoked_out(conn: sqlite3.Connection) -> None:
    row = db.lens_mint_token(conn, label="evil\r\n\x1b[31mphone", max_tokens=1)
    assert row["label"] == "evil[31mphone" and row["token"]
    with pytest.raises(db.LensTokenLimit):
        db.lens_mint_token(conn, label="two", max_tokens=1)
    db.lens_revoke_token(conn, row["id"])
    assert db.lens_mint_token(conn, label="two", max_tokens=1)["token"]


# ------------------------------------------------------------------------ 3. claim rate limit


def test_claim_limit_counts_every_attempt_in_a_burst(conn: sqlite3.Connection, monkeypatch) -> None:
    _slow(monkeypatch, "get_setting")  # old code: all read count=0, all wrote count=1
    results = _burst(40, lambda i: db.lens_claim_attempt(conn, "192.168.1.66", limit=10))
    allowed = [r for r in results if r[0] is True]
    assert len(allowed) == 10, results
    assert db.lens_claim_attempt(conn, "192.168.1.66", limit=10)[0] is False


def test_lockout_is_not_erased_by_a_late_writer(conn: sqlite3.Connection) -> None:
    for _ in range(10):
        assert db.lens_claim_attempt(conn, "192.168.1.66", limit=10)[0] is True
    allowed, retry = db.lens_claim_attempt(conn, "192.168.1.66", limit=10)
    assert allowed is False and retry > 0
    # Burst after the lockout: nothing gets through, and the lockout is still recorded.
    results = _burst(20, lambda i: db.lens_claim_attempt(conn, "192.168.1.66", limit=10))
    assert all(r[0] is False and r[1] > 0 for r in results), results
    lockout_rows = db.query(conn, "SELECT count(*) AS n FROM events WHERE message LIKE 'too many Lens pairing%'")
    assert int(lockout_rows[0]["n"]) == 1, "one events row per lockout, not per guess"


def test_ipv6_claimants_are_counted_per_64(conn: sqlite3.Connection) -> None:
    for i in range(10):
        assert db.lens_claim_attempt(conn, f"2001:db8:1:2::{i + 1:x}", limit=10)[0] is True
    assert db.lens_claim_attempt(conn, "2001:db8:1:2::ffff", limit=10)[0] is False
    assert db.lens_claim_attempt(conn, "2001:db8:1:3::1", limit=10)[0] is True  # another /64


def test_ipv4_mapped_counts_as_the_ipv4_address(conn: sqlite3.Connection) -> None:
    for _ in range(10):
        assert db.lens_claim_attempt(conn, "192.168.1.70", limit=10)[0] is True
    assert db.lens_claim_attempt(conn, "::ffff:192.168.1.70", limit=10)[0] is False
    db.lens_claim_reset(conn, "::ffff:192.168.1.70")
    assert db.lens_claim_attempt(conn, "192.168.1.70", limit=10)[0] is True


def test_odd_sources_still_work(conn: sqlite3.Connection) -> None:
    for source in (None, "", "unknown", "fe80::1%eth0", "not an address" * 10):
        assert db.lens_claim_attempt(conn, source, limit=10)[0] is True
        db.lens_claim_reset(conn, source)
