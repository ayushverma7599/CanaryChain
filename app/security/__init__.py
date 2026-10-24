"""Security layer (Member B). Public interface for the gateway/core path:

    record_event(tenant, event_type, details, canary_type=None) -> event_id
    scan_text(source_tenant, text) -> list[event_id of credential-canary trips]

Imports are deferred so importing app.security stays cheap and cycle-free.
"""


def record_event(tenant: str, event_type: str, details: dict, canary_type: str | None = None) -> str:
    """Record a security event in the audit chain; returns its event_id."""
    from app.security.service import get_security_service

    return get_security_service().record_event(tenant, event_type, details, canary_type)


def scan_text(source_tenant: str, text: str) -> list[str]:
    """Scan text delivered to `source_tenant` for other tenants' canary tokens."""
    from app.security.service import get_security_service

    return get_security_service().scan_text(source_tenant, text)


__all__ = ["record_event", "scan_text"]
