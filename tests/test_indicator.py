from src.security_mcp.tools.indicator import analyze_indicator


def test_ip_indicator(monkeypatch):
    result = {
        "success": True,
        "source": "VirusTotal",
        "indicator": "8.8.8.8",
        "data": {},
    }

    intelligence = {
        "reputation": 123,
        "country": "US",
        "continent": "NA",
        "asn": 15169,
        "as_owner": "Google LLC",
        "network": "8.8.8.0/24",
        "regional_internet_registry": "ARIN",
        "analysis_stats": {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 80,
            "undetected": 20,
            "timeout": 0,
        },
        "last_analysis_date": 1234567890,
        "tags": [],
    }

    monkeypatch.setattr(
        "src.security_mcp.tools.indicator.get_ip_report",
        lambda ip: result,
    )

    monkeypatch.setattr(
        "src.security_mcp.tools.indicator.extract_ip_intelligence",
        lambda report: intelligence,
    )

    result = analyze_indicator("8.8.8.8")

    assert result["valid"] is True
    assert result["type"] == "ip"
    assert result["indicator"] == "8.8.8.8"

    assert result["threat_intelligence"]["available"] is True
    assert result["threat_intelligence"]["source"] == "VirusTotal"
    assert (
        result["threat_intelligence"]["data"]["reputation"]
        == 123
    )


def test_hash_indicator():
    result = analyze_indicator(
        "5d41402abc4b2a76b9719d911017c592"
    )

    assert result["valid"] is True
    assert result["type"] == "hash"


def test_domain_indicator():
    result = analyze_indicator("example.com")

    assert result["valid"] is True
    assert result["type"] == "domain"


def test_subdomain_indicator():
    result = analyze_indicator("sub.example.com")

    assert result["valid"] is True
    assert result["type"] == "domain"


def test_unknown_indicator():
    result = analyze_indicator("hello123")

    assert result["valid"] is False
    assert result["type"] == "unknown"


def test_invalid_domain():
    result = analyze_indicator("-example.com")

    assert result["valid"] is False
    assert result["type"] == "unknown"


def test_empty_indicator():
    result = analyze_indicator("")

    assert result["valid"] is False
    assert result["type"] == "unknown"