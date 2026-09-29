import ipaddress
import logging
import re

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
    """Identify an indicator and route it to the appropriate security analysis."""

    value = indicator.strip()

    if not value:
        return {
            "valid": False,
            "type": "unknown",
            "error": "Indicator cannot be empty",
        }

    # Check whether the indicator is an IP address.
    try:
        ipaddress.ip_address(value)

        logger.info("Indicator identified as IP: %s", value)

        return {
            "valid": True,
            "type": "ip",
            "indicator": value,
            "analysis": analyze_ip(value),
        }

    except ValueError:
        pass

    # Check whether the indicator looks like a known hash format.
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        hash_result = analyze_hash(value)

        if hash_result["possible_algorithm"] is not None:
            logger.info(
                "Indicator identified as hash: length=%d",
                len(value),
            )

            return {
                "valid": True,
                "type": "hash",
                "indicator": value,
                "analysis": hash_result,
            }

    # Check whether the indicator has valid domain syntax.
    if is_valid_domain(value):
        logger.info("Indicator identified as domain: %s", value)

        return {
            "valid": True,
            "type": "domain",
            "indicator": value,
            "analysis": investigate_domain(value),
        }

    logger.warning("Unknown indicator type: %s", value)

    return {
        "valid": False,
        "type": "unknown",
        "indicator": value,
        "error": "Unable to determine indicator type",
    }