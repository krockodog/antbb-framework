"""Store: SQLite-Zugriffe sind unter parallelen Threads serialisiert."""
from __future__ import annotations

import sqlite3
import threading
import time

import pytest

from antbb.store import Store, _call_once, _retryable


def test_journal_and_pragmas(tmp_path):
    db = tmp_path / "antbb.db"
    store = Store(str(db))
    try:
        mode = store._conn.execute("PRAGMA journal_mode").fetchone()[0]
        busy = store._conn.execute("PRAGMA busy_timeout").fetchone()[0]
        sync = store._conn.execute("PRAGMA synchronous").fetchone()[0]
        assert str(mode).lower() == "wal"
        assert int(busy) == 30000
        # NORMAL == 1
        assert int(sync) == 1
    finally:
        store.close()


def test_get_setting_list_scopes_list_mems_still_work(tmp_path):
    store = Store(str(tmp_path / "antbb.db"))
    try:
        store.set_setting("admin.attention_seen.test", "1.0")
        assert store.get_setting("admin.attention_seen.test") == "1.0"
        tid = store.add_target("example.test", "t")
        sid = store.add_scope(tid, "domain", "example.test", True)
        scopes = store.list_scopes(tid)
        assert len(scopes) == 1 and scopes[0]["id"] == sid
        mid = store.add_soldier_mem("analysis", "notiz")
        mems = store.list_soldier_mems("analysis")
        assert mems[0]["id"] == mid
        assert mems[0]["text"] == "notiz"
    finally:
        store.close()


def test_nested_lock_no_deadlock(tmp_path):
    """RLock: Methode, die intern weitere Store-Aufrufe macht, darf nicht hängen."""
    store = Store(str(tmp_path / "antbb.db"))
    try:
        with store._lock:
            store.set_setting("k", "v")
            assert store.get_setting("k") == "v"
            tid = store.add_target("nested.test")
            store.add_scope(tid, "domain", "nested.test")
            assert store.list_scopes(tid)
    finally:
        store.close()


def test_concurrent_reads_and_writes(tmp_path):
    store = Store(str(tmp_path / "antbb.db"))
    tid = store.add_target("race.test")
    store.add_scope(tid, "domain", "race.test")
    store.add_soldier_mem("analysis", "start")
    errors: list[BaseException] = []
    stop = threading.Event()

    def worker(n: int) -> None:
        try:
            for i in range(80):
                store.set_setting(f"k{n}", str(i))
                store.get_setting(f"k{n}")
                store.list_scopes(tid)
                store.list_soldier_mems("analysis")
                if i % 10 == 0:
                    store.add_soldier_mem("analysis", f"{n}-{i}")
        except BaseException as exc:  # noqa: BLE001 – Testdiagnose
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
        if t.is_alive():
            stop.set()
            pytest.fail("Thread hat nach 30s nicht geendet (möglicher Deadlock)")
    assert time.time() - t0 < 30
    assert errors == [], errors
    # Daten konsistent lesbar
    assert store.get_setting("k0") != ""
    assert store.list_scopes(tid)
    assert len(store.list_soldier_mems("analysis")) >= 1
    store.close()


def test_retry_once_on_interface_error():
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise sqlite3.InterfaceError("bad parameter or other API misuse")
        return "ok"

    assert _retryable(sqlite3.InterfaceError("bad parameter"))
    assert _retryable(sqlite3.OperationalError("database is locked"))
    assert not _retryable(sqlite3.OperationalError("no such table: x"))
    assert _call_once(flaky) == "ok"
    assert calls["n"] == 2


def test_retry_gives_up_after_one():
    def always():
        raise sqlite3.InterfaceError("bad parameter or other API misuse")

    with pytest.raises(sqlite3.InterfaceError):
        _call_once(always)


def test_backup_still_works(tmp_path):
    store = Store(str(tmp_path / "antbb.db"))
    store.set_setting("bk", "1")
    dest = tmp_path / "copy.db"
    with sqlite3.connect(str(dest)) as bck:
        store._conn.backup(bck)
    store.close()
    raw = sqlite3.connect(str(dest))
    row = raw.execute("SELECT value FROM settings WHERE key=?", ("bk",)).fetchone()
    raw.close()
    assert row[0] == "1"
