"""Tests for the API key manager and rotation logic."""

import time
import pytest
from core.key_manager import (
    KeyManager,
    mask_key,
    STATUS_ACTIVE,
    STATUS_RATE_LIMITED,
    STATUS_INVALID,
    SERVICE_VT,
    SERVICE_ABUSE,
)


def test_mask_key():
    assert mask_key("abcdef1234567890") == "abcd...7890"
    assert mask_key("short") == "***"
    assert mask_key("") == ""


def test_key_rotation_and_cooldown():
    km = KeyManager()
    # Clear any existing test keys
    km.pools[SERVICE_VT] = []

    # Add 2 keys
    km.add_key(SERVICE_VT, "key_vt_alpha_1111111111")
    km.add_key(SERVICE_VT, "key_vt_bravo_2222222222")

    # Round-robin test
    k1, w1 = km.get_next_key(SERVICE_VT)
    k2, w2 = km.get_next_key(SERVICE_VT)
    assert k1 != k2
    assert w1 == 0.0
    assert w2 == 0.0

    # Rate-limit key 1
    km.mark_rate_limited(SERVICE_VT, k1, cooldown_seconds=2)
    # Next should be key 2
    k3, w3 = km.get_next_key(SERVICE_VT)
    assert k3 == k2

    # Rate-limit key 2 as well
    km.mark_rate_limited(SERVICE_VT, k2, cooldown_seconds=2)
    # Now all keys are throttled! Should return wait_time > 0
    k_none, wait_time = km.get_next_key(SERVICE_VT)
    assert k_none is None
    assert wait_time is not None
    assert 0.0 < wait_time <= 2.0

    # Wait for cooldown to expire
    time.sleep(2.1)
    k_recovered, w_recovered = km.get_next_key(SERVICE_VT)
    assert k_recovered is not None
    assert w_recovered == 0.0
