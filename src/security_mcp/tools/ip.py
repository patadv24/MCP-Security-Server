import ipaddress
import logging


logger = logging.getLogger(__name__)


def analyze_ip(ip: str) -> dict:
    """Analyze an IP address and return basic security-relevant properties."""

    try:
        address = ipaddress.ip_address(ip)

        result = {
            "ip": str(address),
            "valid": True,
            "version": f"IPv{address.version}",
            "private": address.is_private,
            "loopback": address.is_loopback,
            "multicast": address.is_multicast,
            "reserved": address.is_reserved,
        }

        logger.info("IP analysis completed for %s", ip)

        return result

    except ValueError:
        logger.warning("Invalid IP address received: %s", ip)

        return {
            "ip": ip,
            "valid": False,
            "error": "Invalid IP address",
        }