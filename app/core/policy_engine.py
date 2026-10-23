"""Small, deterministic request gate; this is not a general safety system.

The initial policy denies prompts that explicitly request disclosure or
exfiltration of credentials. It does not inspect model output or detect every
unsafe request, and it is not a substitute for downstream security controls.
"""

import re
from dataclasses import dataclass

from app.db.database import CoreDatabase


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    rule_id: str
    reason: str


class PolicyEngine:
    """Apply the initial explicit prompt policy before gateway forwarding."""

    def __init__(self, database: CoreDatabase) -> None:
        self.database = database

    def evaluate(self, prompt: str) -> PolicyDecision:
        for rule in self.database.list_defensive_rules(enabled_only=True):
            if re.search(rule.pattern, prompt, re.IGNORECASE):
                return PolicyDecision(False, rule.rule_id, rule.description)
        return PolicyDecision(
            allowed=True,
            rule_id="no-matching-deny-rule",
            reason="No initial deny rule matched; this is not a safety guarantee.",
        )