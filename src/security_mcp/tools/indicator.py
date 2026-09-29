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


def _unavailable_threat_intelligence(reason: str) -> dict:
    """Return a consistent unavailable threat-intelligence result."""

    return {
        "source": "VirusTotal",
        "available": False,
        "data": {
            "error": reason,
        },
    }


def analyze_indicator(
    indicator: str,
    external_lookup: bool = True,
) -> dict:
    """
    Classify an indicator and perform local analysis.

    VirusTotal enrichment can be disabled when the indicator
    should not be submitted to an external intelligence service.
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
        address = ipaddress.ip_address(value)
        normalized_value = str(address)

        local_analysis = analyze_ip(normalized_value)

        if external_lookup:
            vt_report = get_ip_report(normalized_value)

            if vt_report["success"]:
                threat_intelligence = {
                    "source": "VirusTotal",
                    "available": True,
                    "data": extract_ip_intelligence(vt_report),
                }
            else:
                threat_intelligence = {
                    "source": "VirusTotal",
                    "available": False,
                    "data": {
                        "error": vt_report["error"],
                    },
                }
        else:
            threat_intelligence = _unavailable_threat_intelligence(
                "External threat intelligence lookup disabled"
            )

        logger.info(
            "Indicator classified as IP",
        )

        return {
            "valid": True,
            "type": "ip",
            "indicator": normalized_value,
            "analysis": local_analysis,
            "threat_intelligence": threat_intelligence,
        }

    except ValueError:
        pass

    # ---------------------------------------------------------
    # HASH
    # ---------------------------------------------------------

    normalized_hash = value.lower()
    hash_analysis = analyze_hash(normalized_hash)

    if (
        hash_analysis["valid_hex"]
        and hash_analysis["possible_algorithm"]
    ):
        if external_lookup:
            vt_report = get_hash_report(normalized_hash)

            if vt_report["success"]:
                threat_intelligence = {
                    "source": "VirusTotal",
                    "available": True,
                    "data": extract_hash_intelligence(vt_report),
                }
            else:
                threat_intelligence = {
                    "source": "VirusTotal",
                    "available": False,
                    "data": {
                        "error": vt_report["error"],
                    },
                }
        else:
            threat_intelligence = _unavailable_threat_intelligence(
                "External threat intelligence lookup disabled"
            )

        logger.info(
            "Indicator classified as hash",
        )

        return {
            "valid": True,
            "type": "hash",
            "indicator": normalized_hash,
            "analysis": hash_analysis,
            "threat_intelligence": threat_intelligence,
        }

    # ---------------------------------------------------------
    # DOMAIN
    # ---------------------------------------------------------

    normalized_domain = value.rstrip(".").lower()

    if is_valid_domain(normalized_domain):
        local_analysis = investigate_domain(normalized_domain)

        if external_lookup:
            vt_report = get_domain_report(normalized_domain)

            if vt_report["success"]:
                threat_intelligence = {
                    "source": "VirusTotal",
                    "available": True,
                    "data": extract_domain_intelligence(vt_report),
                }
            else:
                threat_intelligence = {
                    "source": "VirusTotal",
                    "available": False,
                    "data": {
                        "error": vt_report["error"],
                    },
                }
        else:
            threat_intelligence = _unavailable_threat_intelligence(
                "External threat intelligence lookup disabled"
            )

        logger.info(
            "Indicator classified as domain",
        )

        return {
            "valid": True,
            "type": "domain",
            "indicator": normalized_domain,
            "analysis": local_analysis,
            "threat_intelligence": threat_intelligence,
        }

    # ---------------------------------------------------------
    # UNKNOWN
    # ---------------------------------------------------------

    logger.warning(
        "Unknown indicator type received",
    )

    return {
        "valid": False,
        "type": "unknown",
        "indicator": value,
        "error": "Unsupported or invalid indicator format",
    }