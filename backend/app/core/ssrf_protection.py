"""
SSRF (Server-Side Request Forgery) Defense Utility
Protects all user-configurable outbound webhook and integration endpoints.
Blocks loopback, private, link-local, multicast, and cloud metadata addresses.
"""
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple


BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "169.254.169.254",
    "metadata",
    "instance-data",
}


def validate_safe_outbound_url(url: str, allow_private: bool = False) -> Tuple[bool, str]:
    """
    Validates that a URL is safe for server-side outbound HTTP requests.
    Returns (is_safe: bool, reason: str).
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string"

    try:
        parsed = urlparse(url.strip())
    except Exception as e:
        return False, f"Malformed URL: {e}"

    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Unsupported scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL missing valid hostname"

    hostname_lower = hostname.lower().strip("[]")

    if hostname_lower in BLOCKED_HOSTNAMES:
        return False, f"Access to restricted hostname '{hostname_lower}' is blocked by SSRF policy."

    if allow_private:
        return True, "Safe"

    # Resolve IP address to detect DNS rebinding or private IP targets
    try:
        addr_info = socket.getaddrinfo(hostname_lower, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return False, f"Could not resolve hostname '{hostname_lower}': {e}"

    for family, _, _, _, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid IP representation: {ip_str}"

        # Block loopback (127.0.0.0/8, ::1)
        if ip.is_loopback:
            return False, f"Access to loopback address ({ip_str}) is prohibited."

        # Block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
        if ip.is_private:
            return False, f"Access to private internal network ({ip_str}) is prohibited."

        # Block link-local (169.254.0.0/16, fe80::/10 - AWS/GCP/Azure instance metadata)
        if ip.is_link_local:
            return False, f"Access to link-local/cloud metadata address ({ip_str}) is prohibited."

        # Block multicast, reserved, unspecified
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return False, f"Access to reserved/multicast address ({ip_str}) is prohibited."

    return True, "Safe"
