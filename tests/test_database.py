"""Tests for SQLite caching and persistence."""

import pytest
from core.database import (
    save_cached_ioc,
    get_cached_ioc,
    clear_cache,
    delete_cache_entry,
    get_cache_stats,
)


def test_sqlite_cache_roundtrip():
    clear_cache()
    val = "185.220.101.5"

    # Initially empty
    assert get_cached_ioc(val) is None

    # Save to cache
    save_cached_ioc(
        ioc_value=val,
        ioc_type="ipv4",
        verdict="Malicious",
        vt_data={"success": True, "malicious": 14},
        abuse_data={"success": True, "data": {"abuse_confidence_score": 100}},
        ttl_hours=1,
    )

    # Retrieve from cache
    cached = get_cached_ioc(val)
    assert cached is not None
    assert cached["ioc_value"] == val
    assert cached["verdict"] == "Malicious"
    assert cached["vt_data"]["malicious"] == 14
    assert cached["abuse_data"]["data"]["abuse_confidence_score"] == 100

    # Hit count increment
    cached2 = get_cached_ioc(val)
    assert cached2["hit_count"] == 2

    # Delete entry
    deleted = delete_cache_entry(val)
    assert deleted is True
    assert get_cached_ioc(val) is None
