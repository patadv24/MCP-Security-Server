import logging

from src.security_mcp.tools.dns import resolve_dns
from src.security_mcp.tools.ip import analyze_ip


logger = logging.getLogger(__name__)


def investigate_domain(domain: str) -> dict:
    """Resolve a domain and analyze its discovered IP addresses."""

    dns_result = resolve_dns(domain)

    if not dns_result["valid"]:
        logger.warning(
            "Domain investigation failed for %s",
            domain.strip(),
        )

        return {
            "domain": domain.strip(),
            "valid": False,
            "error": dns_result["error"],
            "ip_analysis": [],
        }

    ip_analysis = []

    for ip in dns_result["ipv4"]:
        ip_analysis.append(analyze_ip(ip))

    for ip in dns_result["ipv6"]:
        ip_analysis.append(analyze_ip(ip))

    logger.info(
        "Domain investigation completed for %s: analyzed %d IPs",
        domain,
        len(ip_analysis),
    )

    return {
        "domain": dns_result["domain"],
        "valid": True,
        "resolved_ipv4": dns_result["ipv4"],
        "resolved_ipv6": dns_result["ipv6"],
        "ip_analysis": ip_analysis,
    }