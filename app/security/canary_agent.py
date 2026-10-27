"""The four canary types. Each is plain logic with injected I/O so it can be unit-tested.

A canary never writes the audit log itself: it produces CanaryTrip objects, and
the caller (SecurityService, or the sidecar via POST /internal/event) records them.
Markers are fake and uniquely tagged; never use real credentials.
"""

import re
import secrets
import socketserver
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from app.security.constants import TENANTS, UNKNOWN_ACTOR, normalize_tenant, short_name

TOKEN_RE = re.compile(r"CNRY-(red|blue|llm)-[0-9a-f]{32}")
DECOY_PROCESS_PREFIX = "rt_sync_"
LIST_PROCESSES_CMD = ["sh", "-c", "for f in /proc/[0-9]*/cmdline; do tr '\\000' ' ' < \"$f\"; echo; done"]


@dataclass(frozen=True)
class CanaryTrip:
    """A detected boundary touch. `victim` owns the canary; `actor` touched it."""

    canary_type: str
    victim: str
    actor: str
    evidence: str
    extra: dict = field(default_factory=dict)

    def to_event(self) -> dict:
        """Event payload accepted by record_event / POST /internal/event."""
        return {
            "tenant": self.victim,
            "event_type": f"{self.canary_type}_canary_trip",
            "canary_type": self.canary_type,
            "details": {"actor": self.actor, "evidence": self.evidence, **self.extra},
        }


def generate_token(tenant: str) -> str:
    """A fresh fake credential, e.g. CNRY-red-<32 hex>."""
    return f"CNRY-{short_name(tenant)}-{secrets.token_hex(16)}"


class CredentialCanary:
    """Trips when another tenant's planted token shows up in text delivered to a tenant."""

    def __init__(self, known_tokens: Iterable[str] | None = None) -> None:
        # When known tokens are supplied only exact matches count; otherwise the format is trusted.
        self._known = frozenset(known_tokens) if known_tokens is not None else None

    def scan(self, source_tenant: str, text: str) -> list[CanaryTrip]:
        """One trip per distinct foreign token found in `text`."""
        actor = normalize_tenant(source_tenant)
        trips: list[CanaryTrip] = []
        for match in dict.fromkeys(m.group(0) for m in TOKEN_RE.finditer(text)):
            if self._known is not None and match not in self._known:
                continue
            victim = normalize_tenant(match.split("-")[1])
            if victim != actor:
                trips.append(
                    CanaryTrip(
                        "credential",
                        victim,
                        actor,
                        f"token of {victim} found in text delivered to {actor}",
                        {"token_prefix": match[:10]},
                    )
                )
        return trips


class FileCanary:
    """Decoy file in a tenant's volume. Tenants plant it; the watcher reports opens.

    inotify cannot say who opened a file, so attribution is by mount: if exactly one
    other tenant mounts the volume it is the actor, otherwise the actor is "unknown".
    """

    def __init__(self, victim: str, path: str, other_mounts: Iterable[str] = ()) -> None:
        self.victim = normalize_tenant(victim)
        self.path = path
        self._others = tuple(normalize_tenant(t) for t in other_mounts if normalize_tenant(t) != self.victim)
        self._armed = False

    def arm(self) -> None:
        """Start reporting. Call after the decoy is planted so planting is not a trip."""
        self._armed = True

    def on_access(self, kind: str) -> CanaryTrip | None:
        """Handle a file event ("opened", "closed_no_write", ...). None until armed."""
        if not self._armed:
            return None
        actor = self._others[0] if len(self._others) == 1 else UNKNOWN_ACTOR
        return CanaryTrip("file", self.victim, actor, f"decoy file {self.path} {kind}", {"path": self.path})


class _TripHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server.canary.on_connection(self.client_address[0])


class NetworkCanary:
    """TCP listener on a tenant network; any connection is a trip."""

    def __init__(
        self,
        victim: str,
        emit: Callable[[CanaryTrip], None],
        resolve_actor: Callable[[str], str | None],
        host: str = "0.0.0.0",
        port: int = 9999,
    ) -> None:
        self.victim = normalize_tenant(victim)
        self._emit = emit
        self._resolve = resolve_actor
        self._server = socketserver.ThreadingTCPServer((host, port), _TripHandler)
        self._server.daemon_threads = True
        self._server.canary = self
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        """The bound port (useful when started with port 0)."""
        return self._server.server_address[1]

    def on_connection(self, source_ip: str) -> None:
        """Report one connection from `source_ip`."""
        actor = self._resolve(source_ip) or UNKNOWN_ACTOR
        self._emit(
            CanaryTrip("network", self.victim, actor, f"connection to {self.victim} canary port from {source_ip}", {"source_ip": source_ip})
        )

    def start(self) -> None:
        """Serve in a background thread."""
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop serving (if started) and release the port."""
        if self._thread is not None:
            self._server.shutdown()
        self._server.server_close()


def decoy_process_name(tenant: str) -> str:
    """Name of the decoy process planted in a tenant, e.g. rt_sync_red."""
    return f"{DECOY_PROCESS_PREFIX}{short_name(tenant)}"


class ProcessCanary:
    """Looks inside each tenant for another tenant's decoy process (shared PID namespace)."""

    def __init__(self, exec_in_tenant: Callable[[str, list[str]], str], tenants: Iterable[str] = TENANTS) -> None:
        self._exec = exec_in_tenant
        self._tenants = tuple(tenants)
        self._reported: set[tuple[str, str]] = set()

    def probe(self) -> list[CanaryTrip]:
        """Return trips not yet reported (each observer/victim pair is reported once)."""
        trips: list[CanaryTrip] = []
        for observer in self._tenants:
            listing = self._exec(observer, LIST_PROCESSES_CMD)
            for victim in self._tenants:
                pair = (observer, victim)
                if victim != observer and pair not in self._reported and decoy_process_name(victim) in listing:
                    self._reported.add(pair)
                    trips.append(
                        CanaryTrip("process", victim, observer, f"{victim} decoy process visible from {observer}")
                    )
        return trips
