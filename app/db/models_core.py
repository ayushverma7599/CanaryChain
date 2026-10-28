from dataclasses import dataclass


@dataclass(frozen=True)
class CoreRecord:
    id: int
    operation: str
    prompt: str
    result: str | None
    status: str
    rule_id: str | None
    created_at: str
    request_id: str
    result_id: str | None


@dataclass(frozen=True)
class DefensiveRule:
    rule_id: str
    pattern: str
    description: str
    enabled: bool = True