# Cross-owner requests

Format: `FROM <role> TO <role>: <request>`. Each owner edits only their own files; these are the changes B needs elsewhere. B has worked around each one meanwhile (tests use fakes / a scratch app).

## FROM B TO A (Harshit): wire the security router and call the interface

1. `app/main.py`: serve B's routes from the same app (the frontend proxies `/api/` to `core-api:8000`):
   ```python
   from app.api.routes.security import router as security_router
   app.include_router(security_router)
   ```
   Verified in a scratch copy: `/audit`, `/canary`, `/verify` respond and A's existing tests still pass.
2. Core path: call the interface from `app.security` (inject it so tests can use a fake):
   - after the LLM replies and before returning it: `scan_text(requesting_tenant, result)`
   - when the policy engine denies a prompt: `record_event(requesting_tenant, "policy_block", {"rule_id": decision.rule_id})`
   Semantics are in `docs/security-contract.md`. Both can raise `SecurityDatabaseError`; decide whether a security-store outage should fail the request (B suggests: log and still return, since the audit failure is separately visible at `/verify`).
3. The agreed contract has `tenant` in `POST /attack` and `request_id`/`result_id`, `status`, `/defense` rule fields. The current `docs/api-contract.md` documents `{"prompt"}`-only bodies. Security events need the requesting `tenant`, so `CoreRequest` needs it (default `red-team` is fine for the demo).
4. FYI: `requirements.txt` needs nothing from B for core-api (`httpx`, `fastapi`, `pydantic` already there). The canary image has its own `infra/containers/canary/requirements.txt` (`watchdog`).
5. Optional: a shared SQLite helper. `app/db/database.py` is a class tied to the core tables, so `app/db/security_store.py` copies its connection pattern (single connection, RLock, `BEGIN IMMEDIATE`). If you extract a generic helper later, B will switch to it.

## FROM B TO C (Aditya): compose, env, nginx, frontend, CI

1. `frontend/js/api.js`: enable the three endpoints (field names already match `FIELDS` in `dashboard.js`; `/verify` also returns `head_hash`, worth showing):
   ```js
   audit:  { method: 'GET', path: '/api/audit' },
   canary: { method: 'GET', path: '/api/canary' },
   verify: { method: 'GET', path: '/api/verify' }
   ```
2. `frontend/nginx.conf`: `/api/` proxies everything to core-api, which would expose `/api/internal/event` to browsers. Add before `location /api/`:
   ```nginx
   location /api/internal/ { return 404; }
   ```
3. `.env.example`: add `INTERNAL_EVENT_TOKEN=change-me` (any long random string) and `DOCKER_GID=999` (`getent group docker | cut -d: -f3`).
4. `docker-compose.yml`: add to `core-api.environment`: `SECURITY_DATABASE_PATH: /data/security.sqlite3` and `INTERNAL_EVENT_TOKEN: ${INTERNAL_EVENT_TOKEN:?set in .env}`; add to `gateway.environment`: `COLLECTOR_URL: http://core-api:8000/internal/event` and the same `INTERNAL_EVENT_TOKEN`; and add these services (YAML validated against the existing `*hardening` anchor, not run under Docker):
```yaml
  canary-red:
    <<: *hardening
    build: { context: ., dockerfile: infra/containers/canary/Dockerfile }
    command: ["network"]
    environment:
      CANARY_VICTIM: red-team
      INTERNAL_EVENT_URL: http://core-api:8000/internal/event
      INTERNAL_EVENT_TOKEN: ${INTERNAL_EVENT_TOKEN:?set INTERNAL_EVENT_TOKEN in .env}
    networks: [red_net, gateway_api]
    depends_on:
      core-api: { condition: service_healthy }

  canary-blue:
    <<: *hardening
    build: { context: ., dockerfile: infra/containers/canary/Dockerfile }
    command: ["network"]
    environment:
      CANARY_VICTIM: blue-team
      INTERNAL_EVENT_URL: http://core-api:8000/internal/event
      INTERNAL_EVENT_TOKEN: ${INTERNAL_EVENT_TOKEN:?set INTERNAL_EVENT_TOKEN in .env}
    networks: [blue_net, gateway_api]
    depends_on:
      core-api: { condition: service_healthy }

  canary-llm:
    <<: *hardening
    build: { context: ., dockerfile: infra/containers/canary/Dockerfile }
    command: ["network"]
    environment:
      CANARY_VICTIM: client-llm
      INTERNAL_EVENT_URL: http://core-api:8000/internal/event
      INTERNAL_EVENT_TOKEN: ${INTERNAL_EVENT_TOKEN:?set INTERNAL_EVENT_TOKEN in .env}
    networks: [llm_net, gateway_api]
    depends_on:
      core-api: { condition: service_healthy }

  canary-host:                      # file watcher + process probe. Holds the Docker socket: keep off tenant networks.
    <<: *hardening
    build: { context: ., dockerfile: infra/containers/canary/Dockerfile }
    command: ["host"]
    group_add: ["${DOCKER_GID:?set DOCKER_GID in .env (getent group docker | cut -d: -f3)}"]
    environment:
      INTERNAL_EVENT_URL: http://core-api:8000/internal/event
      INTERNAL_EVENT_TOKEN: ${INTERNAL_EVENT_TOKEN:?set INTERNAL_EVENT_TOKEN in .env}
      CANARY_VOLUMES: red-team=/vols/red,blue-team=/vols/blue,client-llm=/vols/llm
    volumes:
      - red_data:/vols/red:ro
      - blue_data:/vols/blue:ro
      - llm_data:/vols/llm:ro
      - /var/run/docker.sock:/var/run/docker.sock
    networks: [gateway_api]
    depends_on:                     # decoys are planted before a tenant turns healthy; arming earlier would trip on planting
      red: { condition: service_healthy }
      blue: { condition: service_healthy }
      llm: { condition: service_healthy }
      core-api: { condition: service_healthy }
```
5. CI: add `pytest tests/unit` and `ruff check` (currently syntax checks only). If ruff's `B008` is enabled, either add `extend-immutable-calls = ["fastapi.Depends", "fastapi.Query"]` under `[tool.ruff.lint.flake8-bugbear]` or ignore it; `Depends(...)` defaults are the standard FastAPI pattern and `core.py` uses them too.
6. Integration test (`tests/integration/`): the demo flow is in `docs/progress/security.md` under "Demo steps".
7. Bug found on the first full run: `frontend` is only on `app_net`, which is `internal: true`, and Docker does not publish ports for containers on internal-only networks, so `127.0.0.1:8081` was unreachable (`docker compose ps` showed no port for it). Fix: a non-internal `edge: {}` network used only by `frontend` (`networks: [app_net, edge]`), as in the compose snippet above.
8. `frontend/js/dashboard.js` `init()` kept the audit, canary and verify controls disabled ("Member B routes stay unavailable") and never wired them, so the dashboard showed "not integrated yet" even with the routes live. The patch enables the three buttons, loads audit + canary + verification in `refreshAll()`, shows `head_hash` in the verify details, and replaces the test that asserted "remain unavailable" with tests for the live, failed and unreachable states (`tests/frontend/dashboard.test.js`).
