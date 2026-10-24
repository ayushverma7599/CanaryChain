# Progress: Member B (security layer)

Branch: `feat/B-security-layer` (based on `integration/team-project`).

## Phases
- [x] Shared names (`app/security/constants.py`), tenant normalization (`red` -> `red-team`)
- [x] Audit hash chain, store, verifier (`audit_chain.py`, `security_store.py`, `verify_chain.py`)
- [x] Severity model + config, ATLAS mapper + data file (all `TODO` -> "unmapped")
- [x] Canaries: credential, file, network, process (`canary_agent.py`), service layer (`service.py`)
- [x] Routes: `/audit`, `/canary`, `/verify`, `/internal/event` (`app/api/routes/security.py`)
- [x] Sidecar runner (`canary_service.py`) + image (`infra/containers/canary/`)
- [x] Gateway reports tenant-to-tenant leaks to `/internal/event`; per-tenant decoy process names; fixed a self-matching decoy check in `tests/isolation_check.sh`
- [x] Docs: `docs/security-contract.md`, `infra/policies/README.md`, `infra/containers/README.md`, `docs/requests.md`
- [x] Local wiring for testing (`main.py`, core path calls, `api.js` + its tests, nginx rule, compose services, `.env.example`, `tests/conftest.py`, `tests/e2e_smoke.sh`, `docs/e2e-testing.md`): these edit A's and C's files, so they ship as one reviewed PR / `docs/requests.md`, not silently
- [ ] Merge: A wires `security_router` + calls `scan_text`/`record_event`; C adds compose services, env, nginx rule, api.js endpoints (see `docs/requests.md`)
- [ ] Fill ATLAS IDs from https://atlas.mitre.org (`app/security/atlas_map.json`, set `status` to `reviewed`)
- [ ] Run the full Docker stack and the demo below (not yet run: no Docker in the build environment)

## Current state
Everything is unit-tested (`python -m pytest tests/unit`: 68 passed, including A's tests). Verified outside Docker: router + `main.py` wiring in a scratch copy, the sidecar in `network` mode posting to a running API (trip appeared at `/canary` with severity 0.336 and the chain verified), and real inotify events (`opened`, `closed_no_write`) on this kernel. **Not verified:** the compose services in `docs/requests.md`, the `host` sidecar with the Docker socket, `docker exec` in `ProcessCanary`.

## Decisions
- `/canary` is a filtered view of `audit_log` (rows with a `canary_type`): one table, no duplication.
- `tenant` in an event is the victim for canary trips (`details.actor` is who touched it); the requester for other events.
- Gateway reports only tenant-actor leaks; host/core-API traffic is covered by `scan_text` on the core path (avoids duplicate alerts).
- `/internal/event` is token-protected and fails closed (503) when `INTERNAL_EVENT_TOKEN` is unset.
- Error bodies for B's routes: `{"error":{"code","message"}}`.

## Commands
```
pip install -r requirements.txt ruff watchdog
python -m pytest tests/unit
ruff check app/security app/api/routes/security.py
docker compose up -d --build && ./tests/isolation_check.sh     # needs Docker
```

## Demo steps (after the merge items above; `tests/e2e_smoke.sh` runs all of them)
1. `./tests/isolation_check.sh` (11/11) and `./demo/normal_traffic.sh 120`; `./demo/breakit.sh status` shows no canary events.
2. `./demo/breakit.sh leak` -> `status` shows a credential trip (red<->blue, severity 0.72, ATLAS `unmapped` until filled).
3. `./demo/breakit.sh net` + connect to a tenant's port 9999 -> network trip.
4. `./demo/breakit.sh tamper` -> `status`: `verified:false` with `first_error_event_id`. Reset with `docker compose down -v`.

## Known issues
- Four ruff `B008` notes on `Depends(...)` (FastAPI idiom).
- Truncation / full-recompute limitation of a plain hash chain; head_hash must be anchored externally (see contract).

## Next step
Send `docs/requests.md` to Harshit and Aditya; once both items are merged, run the demo steps above in Docker and fix whatever the first real run shows.
