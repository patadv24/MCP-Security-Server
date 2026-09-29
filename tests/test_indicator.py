from src.security_mcp.tools.indicator import analyze_indicator


def test_ip_indicator():
    result = analyze_indicator("8.8.8.8")

    assert result["valid"] is True
    assert result["type"] == "ip"
    assert result["indicator"] == "8.8.8.8"


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