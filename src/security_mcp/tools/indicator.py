import ipaddress
import logging
import re

from src.security_mcp.intelligence.virustotal import (
    extract_domain_intelligence,
    extract_hash_intelligence,
    extract_ip_intelligence,
    get_domain_report,
    get_hash_report,
    get_ip_report,
)
from src.security_mcp.tools.hash import analyze_hash
from src.security_mcp.tools.ip import analyze_ip
from src.security_mcp.tools.investigation import investigate_domain

logger = logging.getLogger(__name__)


def is_valid_domain(domain: str) -> bool:
    """Validate the basic syntax of a domain name."""

    if len(domain) > 253:
        return False

    if "." not in domain:
        return False

    labels = domain.rstrip(".").split(".")

    if len(labels) < 2:
        return False

    for label in labels:
        if not 1 <= len(label) <= 63:
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

        if not re.fullmatch(r"[A-Za-z0-9-]+", label):
            return False

    return True


def analyze_indicator(indicator: str) -> dict:
    """
    Classify an indicator and enrich it with local
    security analysis and VirusTotal intelligence.
    """

    value = indicator.strip()

    if not value:
     return {
        "valid": False,
        "type": "unknown",
        "indicator": value,
        "error": "Indicator cannot be empty",
    }
    # ---------------------------------------------------------
    # IP ADDRESS
    # ---------------------------------------------------------

    try:
        ipaddress.ip_address(value)

        local_analysis = analyze_ip(value)
        vt_report = get_ip_report(value)

        if vt_report["success"]:
            threat_intelligence = extract_ip_intelligence(
                vt_report
            )
        else:
            threat_intelligence = {
                "available": False,
                "error": vt_report["error"],
            }

        logger.info(
            "Indicator classified as IP: %s",
            value,
        )

        return {
            "valid": True,
            "type": "ip",
            "indicator": value,
            "analysis": local_analysis,
            "threat_intelligence": {
                "source": "VirusTotal",
                "available": vt_report["success"],
                "data": threat_intelligence,
            },
        }

    except ValueError:
        pass

    # ---------------------------------------------------------
    # HASH
    # ---------------------------------------------------------

    hash_analysis = analyze_hash(value)

    if (
        hash_analysis["valid_hex"]
        and hash_analysis["possible_algorithm"]
    ):
        vt_report = get_hash_report(value)

        if vt_report["success"]:
            threat_intelligence = extract_hash_intelligence(
                vt_report
            )
        else:
            threat_intelligence = {
                "available": False,
                "error": vt_report["error"],
            }

        logger.info(
            "Indicator classified as hash: %s",
            value,
        )

        return {
            "valid": True,
            "type": "hash",
            "indicator": value,
            "analysis": hash_analysis,
            "threat_intelligence": {
                "source": "VirusTotal",
                "available": vt_report["success"],
                "data": threat_intelligence,
            },
        }

    # ---------------------------------------------------------
    # DOMAIN
    # ---------------------------------------------------------

    if is_valid_domain(value):
        local_analysis = investigate_domain(value)
        vt_report = get_domain_report(value)

        if vt_report["success"]:
            threat_intelligence = extract_domain_intelligence(
                vt_report
            )
        else:
            threat_intelligence = {
                "available": False,
                "error": vt_report["error"],
            }

        logger.info(
            "Indicator classified as domain: %s",
            value,
        )

        return {
            "valid": True,
            "type": "domain",
            "indicator": value,
            "analysis": local_analysis,
            "threat_intelligence": {
                "source": "VirusTotal",
                "available": vt_report["success"],
                "data": threat_intelligence,
            },
        }

    # ---------------------------------------------------------
    # UNKNOWN
    # ---------------------------------------------------------

    logger.warning(
        "Unknown indicator type received: %s",
        value,
    )

    return {
        "valid": False,
        "type": "unknown",
        "indicator": value,
        "error": "Unsupported or invalid indicator format",
    }