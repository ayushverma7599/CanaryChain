# Security layer contract (Member B)

Owner: B. Complements `docs/api-contract.md` (owner A). Verified against `tests/unit/test_security_api.py`.

## Interface for the core path (import from `app.security`)

```python
record_event(tenant: str, event_type: str, details: dict, canary_type: str | None = None) -> str   # event_id
scan_text(source_tenant: str, text: str) -> list[str]   # event_ids of credential-canary trips
```

- `tenant` = the tenant the event is about. For a canary trip: the owner of the canary (victim), with `details["actor"]` naming who touched it. For other events (for example `policy_block`): the requesting tenant.
- `scan_text(source_tenant, text)`: `source_tenant` is the tenant the text is **delivered to**. A token belonging to a different tenant appearing in it is a credential trip (actor = `source_tenant`, victim = token owner).
- Tenants: `red-team`, `blue-team`, `client-llm` (short names `red`, `blue`, `llm` are accepted and normalized). Canary types: `file`, `credential`, `network`, `process`.
- Raises `ValueError` for an unknown tenant or canary type. Raises `SecurityDatabaseError` if storage fails.

## Audit hash rule (implemented only in `app/security/audit_chain.py`)

```
entry_hash = SHA-256( canonical_json(fields) + prev_hash )
canonical_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))   # UTF-8
first prev_hash = "GENESIS"
fields = event_id, timestamp (UTC ISO-8601, microseconds), tenant, event_type,
         canary_type, atlas_technique, severity_score, details
```

Appends run inside `BEGIN IMMEDIATE`; `prev_hash` is `UNIQUE`, so the chain cannot fork. No code path updates or deletes rows.

## Severity

`severity = boundary_criticality x type_weight x reproducibility`, weights in `app/security/severity_config.json`.
Boundary: victim is `client-llm` = 1.0; red<->blue = 0.9; anything else (including actor `unknown`) = 0.6.
Type: credential 1.0, file 0.8, network 0.7, process 0.6. Reproducibility: first trip 0.8; same victim+actor+type again within 60 s = 1.0.
All three factors are stored in `details.severity_factors`. Non-canary events have `severity_score: null`.
Example: red<->blue file trip, repeated: 0.9 x 0.8 x 1.0 = 0.72.

## ATLAS

`app/security/atlas_map.json`, looked up against ATLAS data version 2026.07. Each entry has a `status`:
`TODO` (no suitable technique found), `proposed` (candidate from public sources, not yet checked by a team member) and `reviewed` (checked on https://atlas.mitre.org by a team member). **Only `reviewed` entries are shown; everything else is reported as `unmapped`.**

| Event | Candidate | Tactic | Fit |
|---|---|---|---|
| `credential_canary_trip` | AML.T0057 LLM Data Leakage | Exfiltration | strong |
| `file_canary_trip` | AML.T0035 AI Artifact Collection | Collection | moderate |
| `policy_block` | AML.T0051 LLM Prompt Injection | Execution | moderate (attempt, blocked) |
| `network_canary_trip`, `process_canary_trip` | none found | | leave `unmapped` |

To publish a mapping: open the technique page on atlas.mitre.org, confirm the ID, name and tactic, then set `status` to `reviewed`.

## Endpoints

| Route | Response |
|---|---|
| `GET /audit?limit=200` | `{"items":[{event_id, timestamp, tenant, actor, event_type, atlas_technique, severity_score, entry_hash}]}` newest first. `actor` = who touched the canary (null for events without one, e.g. a policy block) |
| `GET /canary?limit=200` | `{"items":[{event_id, timestamp, tenant, actor, canary_type, atlas_technique, severity_score}]}` newest first |
| `GET /verify` | `{"verified": bool, "checked_entries": int, "first_error_event_id": str\|null, "head_hash": str\|null}`. A failed verification is HTTP 200 with `verified:false`. `head_hash` = hash of the last entry that passed. |
| `POST /internal/event` | body `{tenant, event_type, canary_type?, details}`, header `X-Internal-Token`. 201 `{"event_id"}`; 401 bad token; 503 `internal_events_disabled` if `INTERNAL_EVENT_TOKEN` is unset; 422 invalid event |

Errors: `{"error":{"code","message"}}` (503 `security_store_unavailable` when storage is down).
`/canary` is a filtered view of the same audit table (rows with a `canary_type`); there is no separate canary table, so the two cannot disagree.

## Environment

| Variable | Used by | Purpose |
|---|---|---|
| `SECURITY_DATABASE_PATH` | core-api | audit database file (default `~/.canarychain/security.sqlite3`) |
| `INTERNAL_EVENT_TOKEN` | core-api, gateway, canary sidecars | shared secret for `/internal/event` |
| `COLLECTOR_URL` | gateway | e.g. `http://core-api:8000/internal/event` |
| `INTERNAL_EVENT_URL`, `CANARY_VICTIM`, `CANARY_PORT`, `CANARY_VOLUMES`, `CANARY_MOUNTS`, `CANARY_PROBE_SECONDS` | canary sidecars | see `app/security/canary_service.py` |

## Known limitations

- A plain hash chain detects edits and mid-log deletions but not deleted trailing entries or a full rewrite with every hash recomputed (covered by `test_deleted_trailing_entry_is_not_detected_without_external_anchor`). Save `head_hash` externally (a git commit, a slide screenshot) and, optionally, HMAC-sign entries with a key kept outside the volume.
- The audit database sits in a volume the API process can write. Separating the writer into its own container is the stronger design.
- File canary attribution is by mount (inotify has no PID); `fanotify` would fix it.
- The process canary only trips on PID-namespace misconfiguration.
- Docker socket access for the host sidecar is a powerful privilege.
- Credential detection matches the `CNRY-<tenant>-<32 hex>` format; a tenant can forge a marker to cause a false alert. Pass the real tokens to `CredentialCanary(known_tokens=...)` to require exact matches.
