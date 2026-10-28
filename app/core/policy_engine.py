"""Small, deterministic request gate; this is not a general safety system.

The initial policy denies prompts that explicitly request disclosure or
exfiltration of credentials. It does not inspect model output or detect every
unsafe request, and it is not a substitute for downstream security controls.
"""

import re
from dataclasses import dataclass

from app.db.database import CoreDatabase

# A group that contains a quantifier and is itself quantified, e.g. (a+)+ or (.*)*: the classic
# catastrophic-backtracking shape. This is a heuristic, not a proof of safety.
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*{]")


def rule_id_for(name: str) -> str:
    """Stable rule id from a rule name, so saving the same name again updates the rule."""
    rule_id = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60].strip("-")
    if not rule_id:
        raise ValueError("rule name must contain letters or digits")
    return rule_id


def validate_rule_pattern(pattern: str) -> None:
    """Reject patterns that do not compile or that look prone to catastrophic backtracking."""
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError("rule is not a valid regular expression") from exc
    if _NESTED_QUANTIFIER.search(pattern):
        raise ValueError("rule contains a nested quantifier, which can make matching extremely slow")


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