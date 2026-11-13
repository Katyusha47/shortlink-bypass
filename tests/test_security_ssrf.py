"""Tests for SSRF, DNS Rebinding, and URL Validation Security Layer."""

import pytest
from app.core.security import (
    validate_and_normalize_url,
    verify_target_safety,
    is_ip_forbidden,
    SSRFSecurityError,
    InvalidURLError,
)
import ipaddress


def test_validate_and_normalize_valid_urls():
    assert validate_and_normalize_url("https://bit.ly/test") == "https://bit.ly/test"
    # Auto-prepend https:// if omitted
    assert validate_and_normalize_url("tinyurl.com/abc") == "https://tinyurl.com/abc"
    # Strips fragment
    assert validate_and_normalize_url("https://example.com/page#section") == "https://example.com/page"
    # Lowercase scheme and host
    assert validate_and_normalize_url("HTTP://EXAMPLE.COM/Path") == "http://example.com/Path"


def test_reject_invalid_schemes():
    with pytest.raises(InvalidURLError):
        validate_and_normalize_url("file:///etc/passwd")

    with pytest.raises(InvalidURLError):
        validate_and_normalize_url("gopher://127.0.0.1:70")

    with pytest.raises(InvalidURLError):
        validate_and_normalize_url("javascript:alert(1)")

    with pytest.raises(InvalidURLError):
        validate_and_normalize_url("ftp://ftp.example.com")


def test_reject_credentials_in_url():
    with pytest.raises(InvalidURLError):
        validate_and_normalize_url("https://admin:password@example.com/secret")


def test_reject_blocked_ports():
    with pytest.raises(SSRFSecurityError):
        validate_and_normalize_url("http://example.com:22/")

    with pytest.raises(SSRFSecurityError):
        validate_and_normalize_url("http://example.com:6379/")

    with pytest.raises(SSRFSecurityError):
        validate_and_normalize_url("http://example.com:27017/")


def test_forbidden_ipv4_ranges():
    # Loopback
    assert is_ip_forbidden(ipaddress.ip_address("127.0.0.1")) is True
    assert is_ip_forbidden(ipaddress.ip_address("127.12.34.56")) is True

    # RFC 1918 Private networks
    assert is_ip_forbidden(ipaddress.ip_address("10.0.0.1")) is True
    assert is_ip_forbidden(ipaddress.ip_address("10.254.254.1")) is True
    assert is_ip_forbidden(ipaddress.ip_address("172.16.0.1")) is True
    assert is_ip_forbidden(ipaddress.ip_address("172.31.255.255")) is True
    assert is_ip_forbidden(ipaddress.ip_address("192.168.0.1")) is True
    assert is_ip_forbidden(ipaddress.ip_address("192.168.100.50")) is True

    # Cloud metadata / Link-local
    assert is_ip_forbidden(ipaddress.ip_address("169.254.169.254")) is True
    assert is_ip_forbidden(ipaddress.ip_address("169.254.1.1")) is True

    # CGNAT
    assert is_ip_forbidden(ipaddress.ip_address("100.64.0.1")) is True
    assert is_ip_forbidden(ipaddress.ip_address("100.127.255.255")) is True

    # Public IP (should NOT be forbidden)
    assert is_ip_forbidden(ipaddress.ip_address("8.8.8.8")) is False
    assert is_ip_forbidden(ipaddress.ip_address("1.1.1.1")) is False
    assert is_ip_forbidden(ipaddress.ip_address("104.26.10.228")) is False


def test_forbidden_ipv6_ranges():
    # Loopback
    assert is_ip_forbidden(ipaddress.ip_address("::1")) is True

    # Unique Local Address (ULA)
    assert is_ip_forbidden(ipaddress.ip_address("fc00::1")) is True
    assert is_ip_forbidden(ipaddress.ip_address("fd12:3456:789a::1")) is True

    # Link-local
    assert is_ip_forbidden(ipaddress.ip_address("fe80::1")) is True

    # IPv4-mapped IPv6 private
    assert is_ip_forbidden(ipaddress.ip_address("::ffff:127.0.0.1")) is True
    assert is_ip_forbidden(ipaddress.ip_address("::ffff:192.168.1.1")) is True
    assert is_ip_forbidden(ipaddress.ip_address("::ffff:169.254.169.254")) is True

    # Public IPv6 (should NOT be forbidden)
    assert is_ip_forbidden(ipaddress.ip_address("2606:4700:4700::1111")) is False


def test_blocked_hostnames_direct():
    with pytest.raises(SSRFSecurityError):
        verify_target_safety("http://localhost:8000")

    with pytest.raises(SSRFSecurityError):
        verify_target_safety("http://foo.localhost/api")

    with pytest.raises(SSRFSecurityError):
        verify_target_safety("http://metadata.google.internal/computeMetadata/v1/")

    with pytest.raises(SSRFSecurityError):
        verify_target_safety("http://169.254.169.254/latest/meta-data/")

    with pytest.raises(SSRFSecurityError):
        verify_target_safety("http://127.0.0.1/admin")


def test_dns_rebinding_simulation(monkeypatch):
    """Simulate DNS resolver returning an internal IP address."""
    import socket

    def mock_getaddrinfo(host, port, proto=0):
        # Pretend attacker-controlled domain resolves to internal IP
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    with pytest.raises(SSRFSecurityError) as exc_info:
        verify_target_safety("http://evil-attacker-site.com/rebinding")
    assert "restricted IP address" in str(exc_info.value)

