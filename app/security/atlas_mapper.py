"""Map event types to reviewed MITRE ATLAS labels, or "unmapped"."""

import json
from pathlib import Path

UNMAPPED = "unmapped"
_DEFAULT_MAP = Path(__file__).with_name("atlas_map.json")


class AtlasMapper:
    """Looks up ATLAS labels in a data file; never invents an ID."""

    def __init__(self, mapping: dict | None = None) -> None:
        if mapping is None:
            mapping = json.loads(_DEFAULT_MAP.read_text(encoding="utf-8"))
        self._mapping = mapping

    def lookup(self, event_type: str) -> str:
        """Return "<id> <name>" for a reviewed mapping, otherwise "unmapped"."""
        entry = self._mapping.get(event_type)
        if not isinstance(entry, dict) or entry.get("status") != "reviewed":
            return UNMAPPED
        technique_id, name = entry.get("technique_id"), entry.get("technique_name")
        if not technique_id or not name:
            return UNMAPPED
        return f"{technique_id} {name}"
