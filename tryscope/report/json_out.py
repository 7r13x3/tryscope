"""
TryScope - JSON export
"""
import json
from pathlib import Path

from .. import logger


def save(data: dict, path: str) -> str:
    """Save the full result as JSON."""
    try:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8"
        )
        logger.ok(f"JSON saved: {out}")
        return str(out)
    except Exception as e:
        logger.warn(f"JSON save failed: {e}")
        return ""
