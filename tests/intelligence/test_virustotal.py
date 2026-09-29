import pytest

from src.security_mcp.intelligence import virustotal


def test_get_api_key(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-api-key")

    assert virustotal.get_api_key() == "test-api-key"


def test_get_api_key_missing(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)

    with pytest.raises(
        RuntimeError,
        match="VT_API_KEY is not configured",
    ):
        virustotal.get_api_key()


def test_get_ip_report_success(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "data": {
                    "id": "8.8.8.8",
                    "type": "ip_address",
                    "attributes": {
                        "country": "US",
                        "reputation": 123,
                    },
                }
            }

    def fake_get(url, headers, timeout):
        assert url == (
            "https://www.virustotal.com/api/v3/"
            "ip_addresses/8.8.8.8"
        )
        assert headers["x-apikey"] == "test-api-key"
        assert headers["accept"] == "application/json"
        assert timeout == 10

        return FakeResponse()

    monkeypatch.setenv("VT_API_KEY", "test-api-key")
    monkeypatch.setattr(
        virustotal.requests,
        "get",
        fake_get,
    )

    result = virustotal.get_ip_report("8.8.8.8")

    assert result["success"] is True
    assert result["source"] == "VirusTotal"
    assert result["indicator"] == "8.8.8.8"
    assert result["data"]["data"]["attributes"]["reputation"] == 123


def test_get_ip_report_http_error(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            raise virustotal.requests.HTTPError(
                "403 Client Error"
            )

    def fake_get(url, headers, timeout):
        return FakeResponse()

    monkeypatch.setenv("VT_API_KEY", "test-api-key")
    monkeypatch.setattr(
        virustotal.requests,
        "get",
        fake_get,
    )

    result = virustotal.get_ip_report("8.8.8.8")

    assert result["success"] is False
    assert result["source"] == "VirusTotal"
    assert result["indicator"] == "8.8.8.8"
    assert "403 Client Error" in result["error"]


def test_extract_ip_intelligence():
    fake_report = {
        "data": {
            "data": {
                "attributes": {
                    "reputation": 123,
                    "country": "US",
                    "continent": "NA",
                    "asn": 15169,
                    "as_owner": "Google LLC",
                    "network": "8.8.8.0/24",
                    "regional_internet_registry": "ARIN",
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 1,
                        "harmless": 80,
                        "undetected": 20,
                        "timeout": 0,
                    },
                    "last_analysis_date": 1234567890,
                    "tags": ["cloud", "dns"],
                }
            }
        }
    }

    result = virustotal.extract_ip_intelligence(
        fake_report
    )

    assert result["reputation"] == 123
    assert result["country"] == "US"
    assert result["continent"] == "NA"
    assert result["asn"] == 15169
    assert result["as_owner"] == "Google LLC"
    assert result["network"] == "8.8.8.0/24"
    assert result["regional_internet_registry"] == "ARIN"

    assert result["analysis_stats"]["malicious"] == 0
    assert result["analysis_stats"]["suspicious"] == 1
    assert result["analysis_stats"]["harmless"] == 80
    assert result["analysis_stats"]["undetected"] == 20
    assert result["analysis_stats"]["timeout"] == 0

    assert result["last_analysis_date"] == 1234567890
    assert result["tags"] == ["cloud", "dns"]

    # Assessment
    assert result["assessment"]["malicious_detections"] == 0
    assert result["assessment"]["suspicious_detections"] == 1
    assert result["assessment"]["harmless_detections"] == 80
    assert result["assessment"]["undetected_detections"] == 20
    assert result["assessment"]["timeout_detections"] == 0
    assert result["assessment"]["total_engines"] == 101
    assert result["assessment"]["detection_ratio"] == 0.0099


def test_get_domain_report_success(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "data": {
                    "id": "example.com",
                    "type": "domain",
                    "attributes": {
                        "reputation": 100,
                    },
                }
            }

    def fake_get(url, headers, timeout):
        assert url == (
            "https://www.virustotal.com/api/v3/"
            "domains/example.com"
        )
        assert headers["x-apikey"] == "test-api-key"
        assert headers["accept"] == "application/json"
        assert timeout == 10

        return FakeResponse()

    monkeypatch.setenv("VT_API_KEY", "test-api-key")
    monkeypatch.setattr(
        virustotal.requests,
        "get",
        fake_get,
    )

    result = virustotal.get_domain_report(
        "example.com"
    )

    assert result["success"] is True
    assert result["source"] == "VirusTotal"
    assert result["indicator"] == "example.com"
    assert (
        result["data"]["data"]["attributes"]["reputation"]
        == 100
    )


def test_get_hash_report_success(monkeypatch):
    hash_value = (
        "5d41402abc4b2a76b9719d911017c592"
    )

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "data": {
                    "id": hash_value,
                    "type": "file",
                    "attributes": {
                        "md5": hash_value,
                    },
                }
            }

    def fake_get(url, headers, timeout):
        assert url == (
            "https://www.virustotal.com/api/v3/"
            f"files/{hash_value}"
        )
        assert headers["x-apikey"] == "test-api-key"
        assert headers["accept"] == "application/json"
        assert timeout == 10

        return FakeResponse()

    monkeypatch.setenv("VT_API_KEY", "test-api-key")
    monkeypatch.setattr(
        virustotal.requests,
        "get",
        fake_get,
    )

    result = virustotal.get_hash_report(hash_value)

    assert result["success"] is True
    assert result["source"] == "VirusTotal"
    assert result["indicator"] == hash_value
    assert (
        result["data"]["data"]["attributes"]["md5"]
        == hash_value
    )


def test_extract_domain_intelligence():
    fake_report = {
        "data": {
            "data": {
                "attributes": {
                    "reputation": 100,
                    "categories": {
                        "Forcepoint ThreatSeeker":
                            "Internet Services",
                    },
                    "registrar": "Example Registrar",
                    "creation_date": 1234567890,
                    "first_seen_date": 1234567890,
                    "jarm": "test-jarm",
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 1,
                        "harmless": 80,
                        "undetected": 20,
                        "timeout": 0,
                    },
                    "last_analysis_date": 1234567890,
                    "tags": ["test"],
                    "whois_date": 1234567890,
                }
            }
        }
    }

    result = virustotal.extract_domain_intelligence(
        fake_report
    )

    assert result["reputation"] == 100
    assert result["categories"] == {
        "Forcepoint ThreatSeeker":
            "Internet Services"
    }
    assert result["registrar"] == "Example Registrar"
    assert result["creation_date"] == 1234567890
    assert result["first_seen_date"] == 1234567890
    assert result["jarm"] == "test-jarm"

    assert result["analysis_stats"]["malicious"] == 0
    assert result["analysis_stats"]["suspicious"] == 1
    assert result["analysis_stats"]["harmless"] == 80
    assert result["analysis_stats"]["undetected"] == 20
    assert result["analysis_stats"]["timeout"] == 0

    assert result["last_analysis_date"] == 1234567890
    assert result["tags"] == ["test"]
    assert result["whois_date"] == 1234567890

    # Assessment
    assert result["assessment"]["malicious_detections"] == 0
    assert result["assessment"]["suspicious_detections"] == 1
    assert result["assessment"]["harmless_detections"] == 80
    assert result["assessment"]["undetected_detections"] == 20
    assert result["assessment"]["timeout_detections"] == 0
    assert result["assessment"]["total_engines"] == 101
    assert result["assessment"]["detection_ratio"] == 0.0099


def test_extract_hash_intelligence():
    hash_value = (
        "5d41402abc4b2a76b9719d911017c592"
    )

    fake_report = {
        "data": {
            "data": {
                "attributes": {
                    "md5": hash_value,
                    "sha1": "test-sha1",
                    "sha256": "test-sha256",
                    "reputation": 50,
                    "size": 12345,
                    "type_description": "ASCII text",
                    "magic": "ASCII text, with no line terminators",
                    "first_submission_date": 1234567890,
                    "last_analysis_date": 1234567890,
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 1,
                        "harmless": 0,
                        "undetected": 0,
                        "timeout": 0,
                    },
                    "tags": ["text"],
                }
            }
        }
    }

    result = virustotal.extract_hash_intelligence(
        fake_report
    )

    assert result["md5"] == hash_value
    assert result["sha1"] == "test-sha1"
    assert result["sha256"] == "test-sha256"
    assert result["reputation"] == 50
    assert result["size"] == 12345
    assert result["type_description"] == "ASCII text"
    assert result["magic"] == (
        "ASCII text, with no line terminators"
    )

    assert result["analysis_stats"]["malicious"] == 0
    assert result["analysis_stats"]["suspicious"] == 1
    assert result["analysis_stats"]["harmless"] == 0
    assert result["analysis_stats"]["undetected"] == 0
    assert result["analysis_stats"]["timeout"] == 0

    assert result["tags"] == ["text"]

    # Assessment
    assert result["assessment"]["malicious_detections"] == 0
    assert result["assessment"]["suspicious_detections"] == 1
    assert result["assessment"]["harmless_detections"] == 0
    assert result["assessment"]["undetected_detections"] == 0
    assert result["assessment"]["timeout_detections"] == 0
    assert result["assessment"]["total_engines"] == 1
    assert result["assessment"]["detection_ratio"] == 1.0


def test_build_assessment():
    stats = {
        "malicious": 2,
        "suspicious": 1,
        "harmless": 50,
        "undetected": 10,
        "timeout": 0,
    }

    result = virustotal.build_assessment(stats)

    assert result["malicious_detections"] == 2
    assert result["suspicious_detections"] == 1
    assert result["harmless_detections"] == 50
    assert result["undetected_detections"] == 10
    assert result["timeout_detections"] == 0
    assert result["total_engines"] == 63
    assert result["detection_ratio"] == 0.0476


def test_build_assessment_empty_stats():
    result = virustotal.build_assessment({})

    assert result["total_engines"] == 0
    assert result["detection_ratio"] == 0.0


def test_request_report_invalid_json(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            raise ValueError("Invalid JSON")

    def fake_get(url, headers, timeout):
        return FakeResponse()

    monkeypatch.setenv("VT_API_KEY", "test-api-key")
    monkeypatch.setattr(
        virustotal.requests,
        "get",
        fake_get,
    )

    result = virustotal.get_ip_report("8.8.8.8")

    assert result["success"] is False
    assert result["source"] == "VirusTotal"
    assert result["indicator"] == "8.8.8.8"
    assert result["error"] == (
        "VirusTotal returned invalid JSON"
    )


def test_request_report_timeout(monkeypatch):
    def fake_get(url, headers, timeout):
        raise virustotal.requests.Timeout(
            "Request timed out"
        )

    monkeypatch.setenv("VT_API_KEY", "test-api-key")
    monkeypatch.setattr(
        virustotal.requests,
        "get",
        fake_get,
    )

    result = virustotal.get_domain_report(
        "example.com"
    )

    assert result["success"] is False
    assert result["source"] == "VirusTotal"
    assert result["indicator"] == "example.com"
    assert "Request timed out" in result["error"]


def test_request_report_http_error(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            raise virustotal.requests.HTTPError(
                "429 Too Many Requests"
            )

    def fake_get(url, headers, timeout):
        return FakeResponse()

    monkeypatch.setenv("VT_API_KEY", "test-api-key")
    monkeypatch.setattr(
        virustotal.requests,
        "get",
        fake_get,
    )

    result = virustotal.get_hash_report(
        "5d41402abc4b2a76b9719d911017c592"
    )

    assert result["success"] is False
    assert result["source"] == "VirusTotal"
    assert (
        result["indicator"]
        == "5d41402abc4b2a76b9719d911017c592"
    )
    assert "429 Too Many Requests" in result["error"]