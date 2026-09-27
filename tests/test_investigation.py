from src.security_mcp.tools.investigation import investigate_domain


def test_domain_investigation():
    result = investigate_domain("example.com")

    assert result["valid"] is True
    assert result["domain"] == "example.com"
    assert len(result["ip_analysis"]) > 0

    for analysis in result["ip_analysis"]:
        assert analysis["valid"] is True
        assert "version" in analysis
        assert "private" in analysis


def test_invalid_domain_investigation():
    result = investigate_domain(
        "this-domain-definitely-does-not-exist-12345.com"
    )

    assert result["valid"] is False
    assert result["ip_analysis"] == []