from src.security_mcp.tools.ip import analyze_ip


def test_valid_public_ipv4():
    result = analyze_ip("8.8.8.8")

    assert result["valid"] is True
    assert result["version"] == "IPv4"
    assert result["private"] is False


def test_valid_private_ipv4():
    result = analyze_ip("192.168.1.10")

    assert result["valid"] is True
    assert result["private"] is True


def test_invalid_ip():
    result = analyze_ip("999.999.999.999")

    assert result["valid"] is False
    assert "error" in result