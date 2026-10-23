"""Ties canaries, ATLAS mapping, severity and the audit chain into one recorder."""

import threading
from collections.abc import Callable
from datetime import timedelta
from functools import lru_cache

from app.db.security_store import SecurityStore, get_security_store
from app.security.atlas_mapper import AtlasMapper
from app.security.audit_chain import AuditChain, utc_now
from app.security.canary_agent import CanaryTrip, CredentialCanary
from app.security.constants import CANARY_TYPES, UNKNOWN_ACTOR, normalize_tenant
from app.security.severity import SeverityModel
from app.security.verify_chain import VerifyResult, verify_chain


class SecurityService:
    """Records security events (labelled, scored, hash-chained) and verifies the log."""

    def __init__(
        self,
        store: SecurityStore,
        chain: AuditChain | None = None,
        credential_canary: CredentialCanary | None = None,
        severity: SeverityModel | None = None,
        atlas: AtlasMapper | None = None,
        clock: Callable = utc_now,
    ) -> None:
        self.store = store
        self._clock = clock
        self._chain = chain or AuditChain(store, clock)
        self._credentials = credential_canary or CredentialCanary()
        self._severity = severity or SeverityModel()
        self._atlas = atlas or AtlasMapper()
        self._lock = threading.Lock()

    def record_event(self, tenant: str, event_type: str, details: dict, canary_type: str | None = None) -> str:
        """Record one event and return its event_id.

        `tenant` is the tenant the event is about: for a canary trip the owner of the
        canary (the victim, with details["actor"] naming who touched it); for other
        events (e.g. a policy block) the requesting tenant. Canary events get a severity
        score; others store null.
        """
        tenant = normalize_tenant(tenant)
        if canary_type is not None and canary_type not in CANARY_TYPES:
            raise ValueError(f"unknown canary type: {canary_type!r}")
        details = dict(details)
        with self._lock:
            severity_score = None
            if canary_type is not None:
                actor = str(details.get("actor", UNKNOWN_ACTOR))
                result = self._severity.score(actor, tenant, canary_type, self._is_repeat(tenant, actor, canary_type))
                severity_score = result.score
                details["severity_factors"] = result.factors
            entry = self._chain.append(
                tenant, event_type, canary_type, self._atlas.lookup(event_type), severity_score, details
            )
        return entry.event_id

    def _is_repeat(self, victim: str, actor: str, canary_type: str) -> bool:
        window_start = (self._clock() - timedelta(seconds=self._severity.repeat_window_seconds)).isoformat(
            timespec="microseconds"
        )
        return any(
            e.tenant == victim and e.canary_type == canary_type and e.details.get("actor") == actor
            for e in self.store.canary_since(window_start)
        )

    def record_trip(self, trip: CanaryTrip) -> str:
        """Record a CanaryTrip produced by a canary."""
        event = trip.to_event()
        return self.record_event(event["tenant"], event["event_type"], event["details"], event["canary_type"])

    def scan_text(self, source_tenant: str, text: str) -> list[str]:
        """Record a credential-canary trip for each foreign token in text delivered to source_tenant."""
        return [self.record_trip(trip) for trip in self._credentials.scan(source_tenant, text)]

    def verify(self) -> VerifyResult:
        """Recompute the whole chain."""
        return verify_chain(self.store)


@lru_cache(maxsize=1)
def get_security_service() -> SecurityService:
    """Process-wide service used by the API and by the module-level functions."""
    return SecurityService(get_security_store())
