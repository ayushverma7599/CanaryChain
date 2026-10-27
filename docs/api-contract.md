# Core API Contract

This document records behavior verified in the current FastAPI schemas, route implementations, gateway client, SQLite repository, and unit tests. It does not define behavior that the code and tests leave unspecified.

## Request Models

The three POST operations accept a JSON object with one defined field:

```json
{"prompt": "text to process"}
```

`prompt` must be a string with a maximum supplied length of 8,000 characters; after that field constraint is checked, the validator trims surrounding whitespace and rejects a blank value. Pydantic validation failures are returned by FastAPI as HTTP `422`. The application does not make a successful request unless the request model validates.

## POST Operations

| Method and path | Verified behavior |
|---|---|
| `POST /attack` | Evaluates the prompt against enabled defensive rules, then on approval uses the LLM client. |
| `POST /query` | Evaluates the prompt against enabled defensive rules, then on approval uses the LLM client. |
| `POST /defense` | Blue Team rule management: with a `{name, rule, enabled}` body it saves or updates a defensive rule (see below). With a `{prompt}` body it behaves like the other two operations. |

The repository does not define different prompt construction or processing behavior for these three operations. They currently share the same processing path; the operation name is recorded and returned as a label. Do not infer distinct attack, query, or defense semantics from the paths alone.

### Approved Request

The API sends the validated prompt through `LLMClient` and `GatewayClient` to the existing gateway endpoint `POST /llm/v1/chat`. The application code does not call the LLM tenant directly. On success, the API returns HTTP `200`:

```json
{"operation": "query", "result": "LLM reply"}
```

`operation` is the requested operation name (`attack`, `query`, or `defense`); `result` is the gateway-provided string reply. The completed request/result is stored in the core SQLite database.

### Policy Denial

The policy engine loads enabled rules from the core database. The initial seeded rule denies prompts matching its configured credential-disclosure pattern. This is a narrow text rule, not a general prompt-safety guarantee; it does not inspect model output or establish that unflagged prompts are safe.

A matching request returns HTTP `403` and does not call the LLM client or gateway:

```json
{
  "code": "policy_denied",
  "message": "Requests to disclose or exfiltrate credentials are denied.",
  "rule_id": "credential-disclosure-request"
}
```

The decision is logged, and when the database write succeeds a denied core record is persisted with the operation, prompt, status, and rule ID. Denied requests are not returned by `GET /result`, which selects completed records only.

### Upstream and Persistence Errors

- HTTP `502`: the gateway client raises `GatewayError` for an unsuccessful gateway status, transport/timeout failure, invalid JSON, or response without a string `reply`. The route returns `{"detail":"LLM gateway is unavailable or returned an invalid response"}`. A `gateway_error` core record is saved when persistence succeeds.
- HTTP `503`: policy-rule reads or route persistence operations raise the handled `CoreDatabaseError`. The route returns `{"detail":"Core persistence is unavailable"}`. This response can also occur after an approved gateway call if saving its completed result fails.
- Database initialization occurs in the FastAPI dependency provider before the route executes. The route does not catch initialization errors at that point, so the API does not guarantee the documented HTTP `503` response for that failure.
- The code does not define a custom handler for unexpected exceptions outside these cases, including dependency-initialization failures; their response behavior is not specified here.

## POST /defense: saving a rule

Request:

```json
{"name": "Block Zebra", "rule": "zebra", "enabled": true}
```

- `name`: 1 to 80 characters. The rule id is derived from it (lower-cased, runs of other characters become `-`), so saving the same name again **updates** that rule. A name with no letters or digits is rejected.
- `rule`: 1 to 200 characters, a case-insensitive regular expression searched in prompts. It must compile and must not contain a quantified group that itself contains a quantifier (for example `(a+)+`), which is a heuristic guard against catastrophic backtracking; it is not a proof that every pattern is fast.
- `enabled`: defaults to `true`. A disabled rule is stored but not applied.

Response `200`: `{"rule_id": "block-zebra", "status": "saved"}`. Invalid input returns `422` with `{"detail": "..."}`; a persistence failure returns `503` as for the other routes.

The saved rule is read by the policy engine on the next request, so a matching `POST /attack` returns the `403` policy denial with that `rule_id`. Each save is recorded in the audit chain as `defense_rule_saved` for `blue-team` (`details`: `rule_id`, `enabled`).

A body that contains neither shape returns `422`. Any enabled rule, including a broad one such as `.`, will deny every matching prompt: the Blue Team is trusted to manage rules.

## GET /result

Returns HTTP `200` with the latest record whose status is `completed`, projected into the existing response schema:

```json
{"result":{"operation":"query","result":"LLM reply"}}
```

If no completed record exists, it returns:

```json
{"result":null}
```

The selection is global to the configured core database, not scoped to a caller, tenant, or operation. Denied and gateway-error records may be stored when their database writes succeed, but are not returned by this endpoint. A handled core database error returns HTTP `503` with `{"detail":"Core persistence is unavailable"}`.

## GET /health

Returns HTTP `200`:

```json
{"status":"ok"}
```

The handler returns this static response. The implementation does not check database availability, gateway reachability, or LLM health; callers must not interpret this endpoint as a dependency/readiness check.

## Persistence Notes

Core request/result records and defensive rules use the Member A core SQLite database, configured with `CORE_DATABASE_PATH` or the implementation's default path. This is separate from Member B's security-event and audit/hash-chain storage. The API has no endpoint for creating, editing, listing, or disabling defensive rules; those behaviors are currently internal repository operations only.

## Contract Gaps

- Distinct semantics for `/attack`, `/query`, and `/defense` are not established by current project documentation or implementation.
- No authentication, authorization, caller identity, tenant scoping, or per-user result isolation is defined by the inspected API code.
- The API does not specify maximum response size, request rate limits, or a stable schema for unexpected framework/internal errors.
- `/health` is a liveness-style response only and has no documented readiness counterpart.
- There is no HTTP contract for managing defensive rules.
