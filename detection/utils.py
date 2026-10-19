"""
Deterministic network and IP utility functions for detection engine.
Contains no wall-clock time references.
"""

from ipaddress import ip_address, ip_network


def is_multicast_or_broadcast(ip_str: str | None) -> bool:
    """
    Checks if an IP address string represents multicast, broadcast, or unspecified address.
    Ignores 255.255.255.255, unspecified (0.0.0.0, ::), and multicast ranges (224.0.0.0/4, ff00::/8).
    Does NOT ignore host addresses like 10.0.1.255.
    """
    if not ip_str:
        return False

    try:
        ip = ip_address(ip_str)
    except ValueError:
        return False

    if ip.is_multicast or ip.is_unspecified:
        return True

    if ip_str == "255.255.255.255":
        return True

    return False


def is_ip_in_networks(ip_str: str | None, networks: list[str]) -> bool:
    """Check if ip_str falls within any of the provided CIDR networks."""
    if not ip_str or not networks:
        return True
    try:
        ip = ip_address(ip_str)
        for net_str in networks:
            if ip in ip_network(net_str, strict=False):
                return True
        return False
    except ValueError:
        return False
