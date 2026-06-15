from __future__ import annotations

import ssl

import pytest

from scripts import verify_mcp


def test_loopback_http_is_allowed() -> None:
    assert verify_mcp.ssl_context("http://localhost:8089/services/mcp", False) is None


def test_remote_http_is_rejected() -> None:
    with pytest.raises(ValueError, match="loopback"):
        verify_mcp.ssl_context("http://splunk.example.com/services/mcp", False)


def test_insecure_tls_is_limited_to_loopback() -> None:
    context = verify_mcp.ssl_context("https://127.0.0.1:8089/services/mcp", True)
    assert context is not None
    assert context.verify_mode == ssl.CERT_NONE
    with pytest.raises(ValueError, match="loopback"):
        verify_mcp.ssl_context("https://splunk.example.com/services/mcp", True)
