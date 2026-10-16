"""Unit tests for Safe URL Redirect Tracer and SSRF Protection."""

import pytest
from core.url_tracer import is_private_or_internal_host, trace_url_redirects


def test_ssrf_blocks_loopback_and_private():
    # Loopback
    is_blocked, reason = is_private_or_internal_host("127.0.0.1")
    assert is_blocked is True
    assert "Loopback" in reason or "Private" in reason

    # Localhost
    is_blocked, reason = is_private_or_internal_host("localhost")
    assert is_blocked is True

    # Private RFC1918
    is_blocked, reason = is_private_or_internal_host("192.168.1.1")
    assert is_blocked is True

    is_blocked, reason = is_private_or_internal_host("10.0.0.1")
    assert is_blocked is True

    # Cloud metadata
    is_blocked, reason = is_private_or_internal_host("169.254.169.254")
    assert is_blocked is True

    # Internal domains
    is_blocked, reason = is_private_or_internal_host("server.internal")
    assert is_blocked is True

    is_blocked, reason = is_private_or_internal_host("corp.local")
    assert is_blocked is True


def test_trace_url_redirects_blocks_ssrf_immediately():
    res = trace_url_redirects("http://127.0.0.1:8080/admin")
    assert res["blocked_ssrf"] is True
    assert "SSRF" in res["error"]
    assert len(res["hops"]) == 1
    assert res["hops"][0]["status_code"] == "BLOCKED_SSRF"
