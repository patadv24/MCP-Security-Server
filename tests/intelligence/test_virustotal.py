import pytest

from src.security_mcp.intelligence import virustotal


def test_get_api_key(monkeypatch):
    """Verify that the VirusTotal API key is loaded correctly."""

    monkeypatch.setenv("VT_API_KEY", "test-api-key")

    assert virustotal.get_api_key() == "test-api-key"


def test_get_api_key_missing(monkeypatch):
    """Verify that a missing API key raises an error."""

    monkeypatch.delenv("VT_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="VT_API_KEY is not configured"):
        virustotal.get_api_key()


def test_get_ip_report_success(monkeypatch):
    """Verify successful VirusTotal IP lookup."""

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
    monkeypatch.setattr(virustotal.requests, "get", fake_get)

    result = virustotal.get_ip_report("8.8.8.8")

    assert result["success"] is True
    assert result["source"] == "VirusTotal"
    assert result["indicator"] == "8.8.8.8"
    assert result["data"]["data"]["attributes"]["reputation"] == 123


def test_get_ip_report_http_error(monkeypatch):
    """Verify that HTTP/API errors are handled safely."""

    class FakeResponse:
        def raise_for_status(self):
            raise virustotal.requests.HTTPError("403 Client Error")

    def fake_get(url, headers, timeout):
        return FakeResponse()

    monkeypatch.setenv("VT_API_KEY", "test-api-key")
    monkeypatch.setattr(virustotal.requests, "get", fake_get)

    result = virustotal.get_ip_report("8.8.8.8")

    assert result["success"] is False
    assert result["source"] == "VirusTotal"
    assert result["indicator"] == "8.8.8.8"
    assert "403 Client Error" in result["error"]