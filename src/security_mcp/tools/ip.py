import ipaddress


def analyze_ip(ip: str) -> dict:
    """Analyze an IP address and return basic security-relevant properties."""

    try:
        address = ipaddress.ip_address(ip)

        return {
            "ip": str(address),
            "valid": True,
            "version": f"IPv{address.version}",
            "private": address.is_private,
            "loopback": address.is_loopback,
            "multicast": address.is_multicast,
            "reserved": address.is_reserved,
        }

    except ValueError:
        return {
            "ip": ip,
            "valid": False,
            "error": "Invalid IP address",
        }