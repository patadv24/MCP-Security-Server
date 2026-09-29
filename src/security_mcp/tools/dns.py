import logging
import socket


logger = logging.getLogger(__name__)


def resolve_dns(domain: str) -> dict:
    """Resolve a domain name to its IPv4 and IPv6 addresses."""

    domain = domain.strip()

    if not domain:
        return {
            "valid": False,
            "error": "Domain cannot be empty",
        }

    try:
        results = socket.getaddrinfo(
            domain,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        ipv4_addresses = set()
        ipv6_addresses = set()

        for result in results:
            address = result[4][0]

            if ":" in address:
                ipv6_addresses.add(address)
            else:
                ipv4_addresses.add(address)

        logger.info(
            "DNS resolution completed: IPv4=%d, IPv6=%d",
            len(ipv4_addresses),
            len(ipv6_addresses),
        )

        return {
            "domain": domain,
            "valid": True,
            "ipv4": sorted(ipv4_addresses),
            "ipv6": sorted(ipv6_addresses),
        }

    except socket.gaierror as error:
        logger.warning("DNS resolution failed")

        return {
            "domain": domain,
            "valid": False,
            "error": f"DNS resolution failed: {error}",
        }