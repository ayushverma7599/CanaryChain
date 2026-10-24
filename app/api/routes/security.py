"""GET /audit, GET /canary, GET /verify and POST /internal/event (Member B)."""

import hmac
import os

from fastapi import APIRouter, Depends, Header, Query
from fastapi.responses import JSONResponse

from app.api.security_schemas import (
    AuditItem,
    AuditResponse,
    CanaryItem,
    CanaryResponse,
    InternalEvent,
    VerifyResponse,
)
from app.db.security_store import SecurityDatabaseError
from app.security.service import SecurityService, get_security_service

router = APIRouter()


def error_response(status: int, code: str, message: str) -> JSONResponse:
    """The contract's error body: {"error": {"code", "message"}}."""
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})


def _store_unavailable() -> JSONResponse:
    return error_response(503, "security_store_unavailable", "Security storage is unavailable")


@router.get("/audit", response_model=AuditResponse)
def get_audit(limit: int = Query(200, ge=1, le=1000), service: SecurityService = Depends(get_security_service)):
    """Newest audit events first."""
    try:
        entries = service.store.list_audit(limit)
    except SecurityDatabaseError:
        return _store_unavailable()
    return AuditResponse(items=[AuditItem(**e.__dict__) for e in entries])


@router.get("/canary", response_model=CanaryResponse)
def get_canary(limit: int = Query(200, ge=1, le=1000), service: SecurityService = Depends(get_security_service)):
    """Newest canary trips first."""
    try:
        entries = service.store.list_canary(limit)
    except SecurityDatabaseError:
        return _store_unavailable()
    return CanaryResponse(items=[CanaryItem(**e.__dict__) for e in entries])


@router.get("/verify", response_model=VerifyResponse)
def get_verify(service: SecurityService = Depends(get_security_service)):
    """Recompute the whole chain. A failed verification is HTTP 200 with verified=false."""
    try:
        return VerifyResponse(**service.verify().to_dict())
    except SecurityDatabaseError:
        return _store_unavailable()


@router.post("/internal/event", status_code=201)
def post_internal_event(
    event: InternalEvent,
    x_internal_token: str | None = Header(default=None),
    service: SecurityService = Depends(get_security_service),
):
    """Record an event from the canary sidecar or gateway. Fails closed without a configured token."""
    expected = os.environ.get("INTERNAL_EVENT_TOKEN")
    if not expected:
        return error_response(503, "internal_events_disabled", "INTERNAL_EVENT_TOKEN is not configured")
    if x_internal_token is None or not hmac.compare_digest(x_internal_token, expected):
        return error_response(401, "unauthorized", "Missing or invalid internal token")
    try:
        event_id = service.record_event(event.tenant, event.event_type, event.details, event.canary_type)
    except ValueError as exc:
        return error_response(422, "invalid_event", str(exc))
    except SecurityDatabaseError:
        return _store_unavailable()
    return {"event_id": event_id}

