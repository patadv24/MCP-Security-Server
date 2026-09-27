import re


HASH_PATTERNS = {
    32: "MD5",
    40: "SHA-1",
    64: "SHA-256",
    96: "SHA-384",
    128: "SHA-512",
}


def analyze_hash(hash_value: str) -> dict:
    """Analyze the structural characteristics of a hexadecimal hash."""

    value = hash_value.strip()

    if not value:
        return {
            "valid": False,
            "error": "Hash value cannot be empty",
        }

    is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", value))
    length = len(value)

    possible_algorithm = HASH_PATTERNS.get(length)

    return {
        "hash": value,
        "valid_hex": is_hex,
        "length": length,
        "possible_algorithm": possible_algorithm,
    }