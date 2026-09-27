import logging
from pathlib import Path


LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "security_mcp.log"


def configure_logging() -> None:
    """Configure application logging for the Security MCP Server."""

    LOG_DIR.mkdir(exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
        ],
        force=True,
    )