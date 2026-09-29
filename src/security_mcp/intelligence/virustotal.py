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


def get_ip_report(ip: str) -> dict:
    """Retrieve a VirusTotal report for an IP address."""

    api_key = get_api_key()

    url = f"{VT_BASE_URL}/ip_addresses/{ip}"

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

        logger.info("VirusTotal IP lookup completed for %s", ip)

        return {
            "success": True,
            "source": "VirusTotal",
            "indicator": ip,
            "data": data,
        }

    except requests.RequestException as error:
        logger.warning(
            "VirusTotal IP lookup failed for %s: %s",
            ip,
            error,
        )

        return {
            "success": False,
            "source": "VirusTotal",
            "indicator": ip,
            "error": str(error),
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
        "last_analysis_date": attributes.get(
            "last_analysis_date"
        ),
        "tags": attributes.get("tags", []),
    }

def get_domain_report(domain: str) -> dict:
    """Retrieve a VirusTotal report for a domain."""

    api_key = get_api_key()

    url = f"{VT_BASE_URL}/domains/{domain}"

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
            "VirusTotal domain lookup completed for %s",
            domain,
        )

        return {
            "success": True,
            "source": "VirusTotal",
            "indicator": domain,
            "data": data,
        }

    except requests.RequestException as error:
        logger.warning(
            "VirusTotal domain lookup failed for %s: %s",
            domain,
            error,
        )

        return {
            "success": False,
            "source": "VirusTotal",
            "indicator": domain,
            "error": str(error),
        }


def get_hash_report(hash_value: str) -> dict:
    """Retrieve a VirusTotal report for a file hash."""

    api_key = get_api_key()

    url = f"{VT_BASE_URL}/files/{hash_value}"

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
            "VirusTotal hash lookup completed for %s",
            hash_value,
        )

        return {
            "success": True,
            "source": "VirusTotal",
            "indicator": hash_value,
            "data": data,
        }

    except requests.RequestException as error:
        logger.warning(
            "VirusTotal hash lookup failed for %s: %s",
            hash_value,
            error,
        )

        return {
            "success": False,
            "source": "VirusTotal",
            "indicator": hash_value,
            "error": str(error),
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
        "tags": attributes.get("tags", []),
    }