"""Security and SSRF protection utilities.

Protects against SSRF, DNS rebinding, loopback, private networks,
cloud metadata endpoints, and malicious scheme injection.
"""

from __future__ import annotations
import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit
from typing import Tuple, List

from app.config import settings


class SecurityError(Exception):
    """Base exception for security-related validation failures."""
    pass


class SSRFSecurityError(SecurityError):
    """Raised when an address resolves to a private, loopback, or metadata network."""
    pass


class InvalidURLError(SecurityError):
    """Raised when an input URL is malformed or uses an unsupported scheme."""
    pass


# Specific blocked CIDR networks
FORBIDDEN_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),         # Private RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (CGNAT)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # Private RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (documentation)
    ipaddress.ip_network("192.168.0.0/16"),     # Private RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmark testing
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
]

FORBIDDEN_IPV6_NETWORKS = [
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local
    ipaddress.ip_network("ff00::/8"),           # Multicast
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "169.254.169.254",
}

DISALLOWED_SCHEMES = {
    "javascript", "data", "file", "gopher", "mailto", "ftp",
    "ssh", "telnet", "dict", "ldap", "tftp", "about"
}


def is_ip_forbidden(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address belongs to any restricted or private network."""
    # Convert IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) to pure IPv4
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True

    if isinstance(ip, ipaddress.IPv4Address):
        for net in FORBIDDEN_IPV4_NETWORKS:
            if ip in net:
                return True
    elif isinstance(ip, ipaddress.IPv6Address):
        for net in FORBIDDEN_IPV6_NETWORKS:
            if ip in net:
                return True

    return False


def validate_and_normalize_url(raw_url: str) -> str:
    """Strictly validate and normalize input URL.
    
    Ensures HTTP/HTTPS protocol, strips fragments and whitespace,
    disallows userinfo/credentials, and validates hostname format.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise InvalidURLError("URL must be a non-empty string.")

    raw_url = raw_url.strip()
    if len(raw_url) > 2048:
        raise InvalidURLError("URL exceeds maximum length of 2048 characters.")

    # Check for disallowed schemes before auto-prepending https
    if ":" in raw_url:
        potential_scheme = raw_url.split(":", 1)[0].lower().strip()
        if potential_scheme in DISALLOWED_SCHEMES:
            raise InvalidURLError(f"Unsupported protocol '{potential_scheme}'. Only HTTP and HTTPS are allowed.")

    # Automatically prepend https:// if scheme is missing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        raw_url = "https://" + raw_url

    parsed = urlsplit(raw_url)

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidURLError(f"Unsupported protocol '{scheme}'. Only HTTP and HTTPS are allowed.")

    if not parsed.hostname:
        raise InvalidURLError("URL does not contain a valid hostname.")

    hostname = parsed.hostname.lower().rstrip(".")
    if len(hostname) > 253:
        raise InvalidURLError("Hostname is too long.")

    # Reject credentials in URL
    if parsed.username or parsed.password:
        raise InvalidURLError("URLs with embedded credentials (user:pass) are not permitted.")

    # Check hostname against known blocked hostnames
    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(".localhost"):
        raise SSRFSecurityError(f"Access to hostname '{hostname}' is blocked for security reasons.")

    # Validate port safely
    try:
        port = parsed.port
    except ValueError as exc:
        raise InvalidURLError(f"Invalid port in URL: {exc}")

    if port is not None:
        if port in settings.BLOCKED_PORTS:
            raise SSRFSecurityError(f"Port {port} is restricted.")
        if port not in (80, 443, 8080, 8443, 8000):
            if port < 80 or port > 65535:
                raise InvalidURLError(f"Invalid port number {port}.")

    # Reconstruct normalized URL (strip fragment to avoid leaking anchors)
    netloc = hostname
    if port and port not in (80, 443):
        netloc = f"{hostname}:{port}"

    normalized_url = urlunsplit((
        scheme,
        netloc,
        parsed.path or "/",
        parsed.query,
        ""  # fragment removed
    ))

    return normalized_url


def resolve_hostname_ips(hostname: str, port: int = 443) -> List[str]:
    """Resolve a hostname to all associated IP addresses using DNS.
    
    Raises SSRFSecurityError if resolution fails or any IP is private/loopback.
    """
    hostname = hostname.lower().rstrip(".")
    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(".localhost"):
        raise SSRFSecurityError(f"Hostname '{hostname}' is blocked.")

    # If hostname is an IP literal, validate directly
    try:
        ip = ipaddress.ip_address(hostname)
        if not settings.ALLOW_PRIVATE_IPS and is_ip_forbidden(ip):
            raise SSRFSecurityError(f"IP address '{ip}' is in a restricted range.")
        return [str(ip)]
    except ValueError:
        pass  # Not an IP literal, resolve via DNS

    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise InvalidURLError(f"Could not resolve hostname '{hostname}': {exc}")
    except Exception as exc:
        raise InvalidURLError(f"DNS lookup error for '{hostname}': {exc}")

    if not addr_info:
        raise InvalidURLError(f"No IP addresses found for hostname '{hostname}'.")

    resolved_ips: List[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
            if not settings.ALLOW_PRIVATE_IPS and is_ip_forbidden(ip):
                raise SSRFSecurityError(
                    f"Hostname '{hostname}' resolved to restricted IP address '{ip_str}'."
                )
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
        except ValueError:
            continue

    if not resolved_ips:
        raise SSRFSecurityError(f"No valid public IP addresses found for '{hostname}'.")

    return resolved_ips


def verify_target_safety(url: str) -> Tuple[str, str, List[str]]:
    """Validate URL, resolve DNS, and verify IP safety.
    
    Returns (normalized_url, hostname, resolved_ips).
    Raises InvalidURLError or SSRFSecurityError.
    """
    normalized_url = validate_and_normalize_url(url)
    parsed = urlsplit(normalized_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    resolved_ips = resolve_hostname_ips(hostname, port)
    return normalized_url, hostname, resolved_ips
