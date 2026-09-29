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