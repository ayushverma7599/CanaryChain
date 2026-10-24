"""Canary sidecar entrypoint. Reports trips to the API over POST /internal/event.

    python -m app.security.canary_service network   # one per tenant network (CANARY_VICTIM)
    python -m app.security.canary_service host      # file watcher + process probe (needs Docker socket)

Environment: INTERNAL_EVENT_URL, INTERNAL_EVENT_TOKEN; network mode: CANARY_VICTIM,
CANARY_PORT (default 9999); host mode: CANARY_VOLUMES ("red-team=/vols/red,..."),
CANARY_MOUNTS ("red-team=client-llm;..." tenants that also mount a volume),
CANARY_PROBE_SECONDS (default 30).
"""

import os
import socket
import subprocess
import sys
import threading
import time

import httpx

from app.security.canary_agent import (
    CanaryTrip,
    FileCanary,
    NetworkCanary,
    ProcessCanary,
)
from app.security.constants import TENANTS, normalize_tenant, short_name

DECOY_FILE = ".rt_findings.json"


def http_emitter(url: str, token: str, client: httpx.Client | None = None):
    """Return an emit(trip) function that POSTs the trip to the API's internal route."""
    http = client or httpx.Client(timeout=5.0)

    def emit(trip: CanaryTrip) -> None:
        try:
            http.post(url, json=trip.to_event(), headers={"X-Internal-Token": token}).raise_for_status()
        except httpx.HTTPError as exc:
            print(f"canary: could not report trip: {exc}", file=sys.stderr, flush=True)

    return emit


def resolve_by_dns(source_ip: str) -> str | None:
    """Map a source IP to a tenant using Docker DNS on the network the sidecar sits on."""
    for tenant in TENANTS:
        try:
            if source_ip in socket.gethostbyname_ex(short_name(tenant))[2]:
                return tenant
        except OSError:
            continue
    return None


def docker_exec(tenant: str, command: list[str]) -> str:
    """Run a command inside a tenant's container via the Docker CLI."""
    container = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"label=com.docker.compose.service={short_name(tenant)}"],
        capture_output=True, text=True, check=True, timeout=10,
    ).stdout.split()
    if not container:
        return ""
    return subprocess.run(
        ["docker", "exec", container[0], *command], capture_output=True, text=True, timeout=10, check=False
    ).stdout


def _parse_pairs(raw: str, sep: str = ",") -> dict[str, str]:
    return dict(pair.split("=", 1) for pair in raw.split(sep) if pair)


def run_network(emit) -> None:
    """Listen on the canary port of one tenant network until killed."""
    canary = NetworkCanary(os.environ["CANARY_VICTIM"], emit, resolve_by_dns, port=int(os.environ.get("CANARY_PORT", "9999")))
    canary.start()
    threading.Event().wait()


def run_host(emit) -> None:
    """Watch decoy files (inotify) and probe tenants for foreign decoy processes."""
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    mounts = {k: v.split("+") for k, v in _parse_pairs(os.environ.get("CANARY_MOUNTS", ""), ";").items()}
    observer = Observer()
    for tenant, volume in _parse_pairs(os.environ.get("CANARY_VOLUMES", "")).items():
        canary = FileCanary(tenant, os.path.join(volume, DECOY_FILE), mounts.get(normalize_tenant(tenant), []))
        handler = make_file_handler(canary, emit, FileSystemEventHandler)
        observer.schedule(handler, volume, recursive=False)
        canary.arm()
    observer.start()
    probe = ProcessCanary(docker_exec)
    interval = float(os.environ.get("CANARY_PROBE_SECONDS", "30"))
    while True:
        for trip in probe.probe():
            emit(trip)
        time.sleep(interval)


def make_file_handler(canary: FileCanary, emit, base):
    """Build a watchdog handler that reports opens/reads of the decoy file."""

    class Handler(base):
        def on_any_event(self, event) -> None:
            if event.is_directory or os.path.basename(event.src_path) != os.path.basename(canary.path):
                return
            if event.event_type == "opened":
                trip = canary.on_access(event.event_type)
                if trip is not None:
                    emit(trip)

    return Handler()


def main(argv: list[str]) -> None:
    """Dispatch on the mode argument."""
    emit = http_emitter(os.environ["INTERNAL_EVENT_URL"], os.environ["INTERNAL_EVENT_TOKEN"])
    {"network": run_network, "host": run_host}[argv[1]](emit)


if __name__ == "__main__":
    main(sys.argv)
