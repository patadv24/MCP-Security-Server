import logging
import os

import requests
from dotenv import load_dotenv


logger = logging.getLogger(__name__)

load_dotenv()

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def get_api_key() -> str:
    """Retrieve the VirusTotal API key from environment variables."""

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        raise RuntimeError("VT_API_KEY is not configured.")

    return api_key


def _request_report(endpoint: str, indicator: str, label: str) -> dict:
    """Request a VirusTotal report for an indicator."""

    api_key = get_api_key()

    url = f"{VT_BASE_URL}/{endpoint}/{indicator}"

    headers = {
        "x-apikey": api_key,
        "accept": "application/json",
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10,
        )

        response.raise_for_status()

        data = response.json()

        logger.info(
            "VirusTotal %s lookup completed",
            label,
        )

        return {
            "success": True,
            "source": "VirusTotal",
            "indicator": indicator,
            "data": data,
        }

    except requests.RequestException as error:
        logger.warning(
            "VirusTotal %s lookup failed: %s",
            label,
            error,
        )

        return {
            "success": False,
            "source": "VirusTotal",
            "indicator": indicator,
            "error": str(error),
        }

    except ValueError:
        logger.warning(
            "VirusTotal %s returned invalid JSON",
            label,
        )

        return {
            "success": False,
            "source": "VirusTotal",
            "indicator": indicator,
            "error": "VirusTotal returned invalid JSON",
        }


def get_ip_report(ip: str) -> dict:
    """Retrieve a VirusTotal report for an IP address."""

    return _request_report(
        "ip_addresses",
        ip,
        "IP",
    )


def get_domain_report(domain: str) -> dict:
    """Retrieve a VirusTotal report for a domain."""

    return _request_report(
        "domains",
        domain,
        "domain",
    )


def get_hash_report(hash_value: str) -> dict:
    """Retrieve a VirusTotal report for a file hash."""

    return _request_report(
        "files",
        hash_value,
        "hash",
    )


def build_assessment(analysis_stats: dict) -> dict:
    """Build normalized assessment metrics from VirusTotal statistics."""

    malicious = analysis_stats.get("malicious", 0)
    suspicious = analysis_stats.get("suspicious", 0)
    harmless = analysis_stats.get("harmless", 0)
    undetected = analysis_stats.get("undetected", 0)
    timeout = analysis_stats.get("timeout", 0)

    total_engines = (
        malicious
        + suspicious
        + harmless
        + undetected
        + timeout
    )

    detection_ratio = (
        (malicious + suspicious) / total_engines
        if total_engines
        else 0.0
    )

    return {
        "malicious_detections": malicious,
        "suspicious_detections": suspicious,
        "harmless_detections": harmless,
        "undetected_detections": undetected,
        "timeout_detections": timeout,
        "total_engines": total_engines,
        "detection_ratio": round(detection_ratio, 4),
    }


def extract_ip_intelligence(report: dict) -> dict:
    """Extract useful security intelligence from a VirusTotal IP report."""

    attributes = report["data"]["data"]["attributes"]

    analysis_stats = attributes.get(
        "last_analysis_stats",
        {},
    )

    return {
        "reputation": attributes.get("reputation"),
        "country": attributes.get("country"),
        "continent": attributes.get("continent"),
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
        "network": attributes.get("network"),
        "regional_internet_registry": attributes.get(
            "regional_internet_registry"
        ),
        "analysis_stats": {
            "malicious": analysis_stats.get("malicious", 0),
            "suspicious": analysis_stats.get("suspicious", 0),
            "harmless": analysis_stats.get("harmless", 0),
            "undetected": analysis_stats.get("undetected", 0),
            "timeout": analysis_stats.get("timeout", 0),
        },
        "assessment": build_assessment(analysis_stats),
        "last_analysis_date": attributes.get(
            "last_analysis_date"
        ),
        "tags": attributes.get("tags", []),
    }


def extract_domain_intelligence(report: dict) -> dict:
    """Extract useful security intelligence from a VirusTotal domain report."""

    attributes = report["data"]["data"]["attributes"]

    analysis_stats = attributes.get(
        "last_analysis_stats",
        {},
    )

    return {
        "reputation": attributes.get("reputation"),
        "categories": attributes.get("categories", {}),
        "registrar": attributes.get("registrar"),
        "creation_date": attributes.get("creation_date"),
        "first_seen_date": attributes.get("first_seen_date"),
        "jarm": attributes.get("jarm"),
        "analysis_stats": {
            "malicious": analysis_stats.get("malicious", 0),
            "suspicious": analysis_stats.get("suspicious", 0),
            "harmless": analysis_stats.get("harmless", 0),
            "undetected": analysis_stats.get("undetected", 0),
            "timeout": analysis_stats.get("timeout", 0),
        },
        "assessment": build_assessment(analysis_stats),
        "last_analysis_date": attributes.get(
            "last_analysis_date"
        ),
        "tags": attributes.get("tags", []),
        "whois_date": attributes.get("whois_date"),
    }


def extract_hash_intelligence(report: dict) -> dict:
    """Extract useful security intelligence from a VirusTotal hash report."""

    attributes = report["data"]["data"]["attributes"]

    analysis_stats = attributes.get(
        "last_analysis_stats",
        {},
    )

    return {
        "md5": attributes.get("md5"),
        "sha1": attributes.get("sha1"),
        "sha256": attributes.get("sha256"),
        "reputation": attributes.get("reputation"),
        "size": attributes.get("size"),
        "type_description": attributes.get(
            "type_description"
        ),
        "magic": attributes.get("magic"),
        "first_submission_date": attributes.get(
            "first_submission_date"
        ),
        "last_analysis_date": attributes.get(
            "last_analysis_date"
        ),
        "analysis_stats": {
            "malicious": analysis_stats.get("malicious", 0),
            "suspicious": analysis_stats.get("suspicious", 0),
            "harmless": analysis_stats.get("harmless", 0),
            "undetected": analysis_stats.get("undetected", 0),
            "timeout": analysis_stats.get("timeout", 0),
        },
        "assessment": build_assessment(analysis_stats),
        "tags": attributes.get("tags", []),
    }