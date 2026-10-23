"""Deterministic severity: boundary_criticality x type_weight x reproducibility.

No model is involved. Weights live in severity_config.json so a reviewer can
recompute any score by hand from the factors stored with the event.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from app.security.constants import BLUE_TEAM, CANARY_TYPES, CLIENT_LLM, RED_TEAM

_DEFAULT_CONFIG = Path(__file__).with_name("severity_config.json")


@dataclass(frozen=True)
class SeverityResult:
    """A severity score together with the three factors that produced it."""

    score: float
    factors: dict[str, float]


class SeverityModel:
    """Computes severity from a weights config."""

    def __init__(self, config: dict | None = None) -> None:
        if config is None:
            config = json.loads(_DEFAULT_CONFIG.read_text(encoding="utf-8"))
        self._boundary = config["boundary_criticality"]
        self._weights = config["type_weight"]
        self._repro = config["reproducibility"]
        missing = [t for t in CANARY_TYPES if t not in self._weights]
        if missing:
            raise ValueError(f"severity config lacks type weights for: {missing}")

    @property
    def repeat_window_seconds(self) -> int:
        """Seconds within which a second identical trip counts as a repeat."""
        return int(self._repro["repeat_window_seconds"])

    def boundary_criticality(self, actor: str, victim: str) -> float:
        """Weight of the boundary that was crossed."""
        if victim == CLIENT_LLM:
            return self._boundary["to_client_llm"]
        if {actor, victim} == {RED_TEAM, BLUE_TEAM}:
            return self._boundary["red_blue"]
        return self._boundary["other"]

    def score(self, actor: str, victim: str, canary_type: str, repeated: bool) -> SeverityResult:
        """Return the severity of one canary trip."""
        if canary_type not in self._weights:
            raise ValueError(f"unknown canary type: {canary_type!r}")
        factors = {
            "boundary_criticality": self.boundary_criticality(actor, victim),
            "type_weight": self._weights[canary_type],
            "reproducibility": self._repro["repeat" if repeated else "first"],
        }
        product = factors["boundary_criticality"] * factors["type_weight"] * factors["reproducibility"]
        return SeverityResult(score=round(product, 4), factors=factors)
