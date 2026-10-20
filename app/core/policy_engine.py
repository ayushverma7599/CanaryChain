"""Small, deterministic request gate; this is not a general safety system.

The initial policy denies prompts that explicitly request disclosure or
exfiltration of credentials. It does not inspect model output or detect every
unsafe request, and it is not a substitute for downstream security controls.
"""

import re
from dataclasses import dataclass


_CREDENTIAL_REQUEST = re.compile(
    r"\b(?:reveal|show|print|expose|steal|leak|exfiltrate)\b"
    r"[\s\S]{0,80}\b(?:api\s*keys?|credentials?|secrets?|tokens?)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    rule_id: str
    reason: str


class PolicyEngine:
    """Apply the initial explicit prompt policy before gateway forwarding."""

    def evaluate(self, prompt: str) -> PolicyDecision:
        if _CREDENTIAL_REQUEST.search(prompt):
            return PolicyDecision(
                allowed=False,
                rule_id="credential-disclosure-request",
                reason="Requests to disclose or exfiltrate credentials are denied.",
            )
        return PolicyDecision(
            allowed=True,
            rule_id="no-matching-deny-rule",
            reason="No initial deny rule matched; this is not a safety guarantee.",
        )