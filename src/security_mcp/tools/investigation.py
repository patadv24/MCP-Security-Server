from src.security_mcp.tools.dns import resolve_dns
from src.security_mcp.tools.ip import analyze_ip


def investigate_domain(domain: str) -> dict:
    """Resolve a domain and analyze its discovered IP addresses."""

    dns_result = resolve_dns(domain)

    if not dns_result["valid"]:
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

    return {
        "domain": dns_result["domain"],
        "valid": True,
        "resolved_ipv4": dns_result["ipv4"],
        "resolved_ipv6": dns_result["ipv6"],
        "ip_analysis": ip_analysis,
    }