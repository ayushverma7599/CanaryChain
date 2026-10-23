import socket
import time

import pytest

from app.security.canary_agent import (
    CanaryTrip,
    CredentialCanary,
    FileCanary,
    NetworkCanary,
    ProcessCanary,
    decoy_process_name,
    generate_token,
)
from app.security.constants import normalize_tenant, short_name


def test_tenant_names_normalize():
    assert normalize_tenant("red") == "red-team" and normalize_tenant("client-llm") == "client-llm"
    assert short_name("blue-team") == "blue"
    with pytest.raises(ValueError):
        normalize_tenant("mallory")


def test_generated_tokens_are_unique_and_tagged():
    a, b = generate_token("red-team"), generate_token("red-team")
    assert a != b and a.startswith("CNRY-red-") and len(a) == len("CNRY-red-") + 32


def test_credential_trip_when_foreign_token_seen():
    token = generate_token("blue-team")
    (trip,) = CredentialCanary().scan("red-team", f"leaked: {token} and again {token}")
    assert (trip.canary_type, trip.victim, trip.actor) == ("credential", "blue-team", "red-team")
    assert token not in str(trip.to_event())  # the full token is never stored


def test_no_trip_for_own_token_or_clean_text():
    own = generate_token("red-team")
    assert CredentialCanary().scan("red-team", f"my own {own}") == []
    assert CredentialCanary().scan("red-team", "nothing here") == []


def test_known_tokens_filter_forged_markers():
    real, forged = generate_token("blue-team"), generate_token("blue-team")
    trips = CredentialCanary(known_tokens=[real]).scan("red-team", f"{real} {forged}")
    assert len(trips) == 1


def test_file_canary_silent_until_armed_then_trips():
    canary = FileCanary("red-team", "/vols/red/.rt_findings.json", other_mounts=["blue-team"])
    assert canary.on_access("opened") is None
    canary.arm()
    trip = canary.on_access("opened")
    assert (trip.canary_type, trip.victim, trip.actor) == ("file", "red-team", "blue-team")


def test_file_canary_actor_unknown_when_attribution_is_ambiguous():
    canary = FileCanary("red-team", "/x", other_mounts=[])
    canary.arm()
    assert canary.on_access("opened").actor == "unknown"


def test_network_canary_trips_on_real_connection():
    trips = []
    canary = NetworkCanary("red-team", trips.append, lambda ip: "blue-team", host="127.0.0.1", port=0)
    canary.start()
    try:
        socket.create_connection(("127.0.0.1", canary.port), timeout=2).close()
        deadline = time.time() + 2
        while not trips and time.time() < deadline:
            time.sleep(0.02)
    finally:
        canary.stop()
    assert trips and (trips[0].victim, trips[0].actor) == ("red-team", "blue-team")


def test_network_canary_unresolved_source_is_unknown():
    trips = []
    canary = NetworkCanary("red-team", trips.append, lambda ip: None, host="127.0.0.1", port=0)
    try:
        canary.on_connection("10.9.9.9")
    finally:
        canary.stop()
    assert trips[0].actor == "unknown" and trips[0].extra["source_ip"] == "10.9.9.9"


def test_process_canary_detects_shared_pid_namespace_once():
    def exec_in(tenant, _cmd):
        if tenant == "blue-team":  # blue can see red's decoy: PID namespace leak
            return f"1 sleep\n7 {decoy_process_name('blue-team')} infinity\n8 {decoy_process_name('red-team')} infinity"
        return f"1 {decoy_process_name(tenant)} infinity"

    probe = ProcessCanary(exec_in)
    (trip,) = probe.probe()
    assert (trip.victim, trip.actor) == ("red-team", "blue-team")
    assert probe.probe() == []  # reported once per pair


def test_process_canary_quiet_when_isolated():
    probe = ProcessCanary(lambda tenant, _cmd: f"1 {decoy_process_name(tenant)} infinity")
    assert probe.probe() == []


def test_trip_event_shape():
    event = CanaryTrip("file", "red-team", "blue-team", "opened", {"path": "/x"}).to_event()
    assert event == {
        "tenant": "red-team",
        "event_type": "file_canary_trip",
        "canary_type": "file",
        "details": {"actor": "blue-team", "evidence": "opened", "path": "/x"},
    }
