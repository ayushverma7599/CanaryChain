# CanaryChain runbook

How to run, check, test and recover the project. Everything here is taken from `docker-compose.yml`, the code and the test suite; the Docker steps have not been run by whoever last edited this file (no Docker in their environment), so treat section 2 as the first thing to confirm on a real machine and fix this file if it differs.

## 1. What runs where

| Service | Port (host) | Role | Healthy when |
|---|---|---|---|
| `red`, `blue`, `llm` | none | Tenant containers, each alone on an `internal` network | `docker compose ps` shows healthy |
| `gateway` | `127.0.0.1:8080` | Only path between tenants and from the core API to the LLM tenant | healthy (TCP check) |
| `core-api` | none (internal) | FastAPI: `/attack /query /defense /result /health /audit /canary /verify /internal/event` | `/health` returns `{"status":"ok"}` |
| `frontend` | `127.0.0.1:8081` | Dashboard; proxies `/api/` to `core-api` and blocks `/api/internal/` | `/healthz` |
| `canary-red/blue/llm` | none | Network canary per tenant network | running |
| `canary-host` | none | File watcher and process probe; holds the Docker socket | running |

Data: `core_data` volume (`/data/core.sqlite3` requests/results/rules, `/data/security.sqlite3` audit chain). `docker compose down -v` deletes it.

## 2. Bring-up

```bash
cp .env.example .env
sed -i "s/^INTERNAL_EVENT_TOKEN=.*/INTERNAL_EVENT_TOKEN=$(openssl rand -hex 24)/" .env
sed -i "s/^DOCKER_GID=.*/DOCKER_GID=$(getent group docker | cut -d: -f3)/" .env
docker compose up -d --build
docker compose ps
curl -s http://127.0.0.1:8081/api/health      # {"status":"ok"}
./tests/isolation_check.sh                    # expect passed=11 failed=0
```

`compose` refuses to start without `INTERNAL_EVENT_TOKEN` and `DOCKER_GID` (`:?` in the file). `.env` is never committed; CI rejects a tracked `.env`.

## 3. Using the API (through the dashboard proxy)

```bash
API=http://127.0.0.1:8081/api
curl -s -XPOST $API/query -H 'Content-Type: application/json' -d '{"prompt":"hello"}'
# {"operation":"query","result":"...","request_id":"req_...","result_id":"res_..."}
curl -s "$API/result"                          # latest completed result, same shape
curl -s "$API/result?result_id=res_..."        # that exact result; unknown id -> 404
```

- `request_id` is returned for every submission that is stored (also in the `403` denial body); `result_id` exists only for a completed result. Details: `docs/api-contract.md`.
- Blue Team rules: `POST /defense` with `{"name","rule","enabled"}`.

| Response | Meaning | What to do |
|---|---|---|
| `403 policy_denied` | A defensive rule matched; the gateway was not called | Expected. `rule_id` says which rule |
| `502` | Gateway/LLM unreachable or invalid reply; a `gateway_error` record was stored | `docker compose ps gateway llm`, `docker compose logs gateway` |
| `503 Core persistence is unavailable` | SQLite read/write failed | Check the `core_data` volume and disk space; `docker compose logs core-api` |
| `404` on `/result?result_id=` | No completed result has that id (a `request_id` does not work) | Use the `result_id` from the POST response |
| `/internal/event` `401` / `503` | Wrong token / token not configured | Compare `INTERNAL_EVENT_TOKEN` in `.env` across services; `docker compose up -d` after editing |

A security-store problem does not fail `/attack` or `/query` (it is logged); it shows up in `/verify`.

## 4. Demo and evidence

See README section 9 and `docs/e2e-testing.md`. Short form: `./demo/breakit.sh leak|net|file|pid`, then `curl $API/canary`, `curl $API/verify`, and `./demo/breakit.sh tamper` followed by `curl $API/verify` (expect `verified:false`). Tampering leaves the stack dirty: reset afterwards.

## 5. Reset and recovery

| Situation | Command |
|---|---|
| Tenant or service wedged | `docker compose up -d --force-recreate <service>` |
| Fresh start (deletes all data) | `docker compose down -v && docker compose up -d --build` |
| Undo `breakit.sh net` / `pid` | `./demo/breakit.sh net-undo` / `pid-undo`, then `./tests/isolation_check.sh` |
| Logs | `docker compose logs --since 10m <service>` |

## 6. Tests and CI (no Docker needed)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
ruff check .                              # config: ruff.toml
python -m pytest                          # tests/unit + tests/integration (pytest.ini)
node --test tests/frontend/*.test.js      # Node 20+
```

`tests/integration/test_inprocess_stack.py` runs the real core app, the real gateway handler and the real stub-LLM tenant on localhost threads. It covers: prompt round trip, `GET /result?result_id=`, a denied prompt never reaching the gateway, a leaked token tripping the credential canary while the request still succeeds, tamper detection on the audit chain, and a gateway outage returning 502.

GitHub Actions (`.github/workflows/ci.yml`) runs on every pull request and on pushes to `main`:

| Job | Runs |
|---|---|
| `baseline` | `docker compose config`, Python and shell syntax, no tracked `.env` |
| `python` | `ruff check .` and `python -m pytest` on Python 3.12 |
| `frontend` | `node --test tests/frontend/*.test.js` on Node 20 |

**Not covered by CI:** anything that needs real containers, namely network isolation (`tests/isolation_check.sh`), the `canary-host` sidecar with the Docker socket, `docker exec` in the process canary, and `tests/e2e_smoke.sh`. Run those by hand before a demo. In the in-process test the gateway's source-IP attribution is stubbed (every caller is `host`), because it depends on Docker DNS.

Lint rules (`ruff.toml`): `E, F, I, B, UP`, ignoring `B008` (FastAPI `Depends`) and `E501`; `gateway/` and `tenants/` are exempt from the compact-style rules because they are deliberately terse stdlib scripts.
