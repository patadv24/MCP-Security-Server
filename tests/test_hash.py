from src.security_mcp.tools.hash import analyze_hash


def test_md5_hash_structure():
    result = analyze_hash("5d41402abc4b2a76b9719d911017c592")

    assert result["valid_hex"] is True
    assert result["length"] == 32
    assert result["possible_algorithm"] == "MD5"


def test_invalid_hex_hash():
    result = analyze_hash("hello123")

    assert result["valid_hex"] is False
    assert result["length"] == 8
    assert result["possible_algorithm"] is None


def test_empty_hash():
    result = analyze_hash("")

    assert result["valid"] is False
    assert "error" in result