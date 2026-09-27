from src.security_mcp.tools.dns import resolve_dns


def test_valid_domain():
    result = resolve_dns("example.com")

    assert result["valid"] is True
    assert result["domain"] == "example.com"
    assert len(result["ipv4"]) > 0


def test_invalid_domain():
    result = resolve_dns(
        "this-domain-definitely-does-not-exist-12345.com"
    )

    assert result["valid"] is False
    assert "error" in result