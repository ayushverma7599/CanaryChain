from typing import Any

from pydantic import BaseModel, Field

from app.security.constants import CANARY_TYPES


class InternalEvent(BaseModel):
    """Body of POST /internal/event (canary sidecar and gateway only)."""

    tenant: str
    event_type: str = Field(min_length=1, max_length=100)
    canary_type: str | None = Field(default=None, pattern="^(" + "|".join(CANARY_TYPES) + ")$")
    details: dict[str, Any] = Field(default_factory=dict)


class AuditItem(BaseModel):
    event_id: str
    timestamp: str
    tenant: str
    actor: str | None
    event_type: str
    atlas_technique: str
    severity_score: float | None
    entry_hash: str


class CanaryItem(BaseModel):
    event_id: str
    timestamp: str
    tenant: str
    actor: str | None
    canary_type: str
    atlas_technique: str
    severity_score: float | None


class AuditResponse(BaseModel):
    items: list[AuditItem]


class CanaryResponse(BaseModel):
    items: list[CanaryItem]


class VerifyResponse(BaseModel):
    verified: bool
    checked_entries: int
    first_error_event_id: str | None
    head_hash: str | None
