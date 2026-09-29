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

def test_analyze_indicator_ip_with_virustotal(monkeypatch):
    def fake_get_ip_report(ip):
        assert ip == "8.8.8.8"
        return {
            "success": True,
            "source": "VirusTotal",
            "indicator": ip,
            "data": {
                "data": {
                    "attributes": {
                        "reputation": 561,
                        "country": "US",
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 53,
                            "undetected": 38,
                            "timeout": 0,
                        },
                    }
                }
            },
        }

    monkeypatch.setattr(
        "src.security_mcp.tools.indicator.get_ip_report",
        fake_get_ip_report,
    )

    result = analyze_indicator("8.8.8.8")

    assert result["valid"] is True
    assert result["type"] == "ip"
    assert result["indicator"] == "8.8.8.8"
    assert result["threat_intelligence"]["available"] is True
    assert result["threat_intelligence"]["data"]["reputation"] == 561


def test_analyze_indicator_domain_with_virustotal(monkeypatch):
    def fake_get_domain_report(domain):
        assert domain == "example.com"
        return {
            "success": True,
            "source": "VirusTotal",
            "indicator": domain,
            "data": {
                "data": {
                    "attributes": {
                        "reputation": 100,
                        "categories": {
                            "Forcepoint ThreatSeeker": "Internet Services",
                        },
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 80,
                            "undetected": 20,
                            "timeout": 0,
                        },
                    }
                }
            },
        }

    def fake_investigate_domain(domain):
        return {
            "domain": domain,
            "valid": True,
            "resolved_ipv4": ["93.184.216.34"],
            "resolved_ipv6": [],
            "ip_analysis": [],
        }

    monkeypatch.setattr(
        "src.security_mcp.tools.indicator.get_domain_report",
        fake_get_domain_report,
    )

    monkeypatch.setattr(
        "src.security_mcp.tools.indicator.investigate_domain",
        fake_investigate_domain,
    )

    result = analyze_indicator("example.com")

    assert result["valid"] is True
    assert result["type"] == "domain"
    assert result["indicator"] == "example.com"
    assert result["threat_intelligence"]["available"] is True
    assert result["threat_intelligence"]["data"]["reputation"] == 100


def test_analyze_indicator_hash_with_virustotal(monkeypatch):
    hash_value = "5d41402abc4b2a76b9719d911017c592"

    def fake_get_hash_report(value):
        assert value == hash_value
        return {
            "success": True,
            "source": "VirusTotal",
            "indicator": value,
            "data": {
                "data": {
                    "attributes": {
                        "md5": value,
                        "sha1": "fake-sha1",
                        "sha256": "fake-sha256",
                        "reputation": -5,
                        "size": 12345,
                        "type_description": "Text",
                        "magic": "ASCII text",
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 1,
                            "harmless": 50,
                            "undetected": 10,
                            "timeout": 0,
                        },
                    }
                }
            },
        }

    monkeypatch.setattr(
        "src.security_mcp.tools.indicator.get_hash_report",
        fake_get_hash_report,
    )

    result = analyze_indicator(hash_value)

    assert result["valid"] is True
    assert result["type"] == "hash"
    assert result["indicator"] == hash_value
    assert result["threat_intelligence"]["available"] is True
    assert result["threat_intelligence"]["data"]["md5"] == hash_value
    assert (
        result["threat_intelligence"]["data"]["analysis_stats"]["malicious"]
        == 2
    )