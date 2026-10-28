import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from app.api.schemas import (
    CoreRequest,
    CoreResponse,
    DefenseRuleRequest,
    DefenseRuleResponse,
    HealthResponse,
    Operation,
    PolicyDenialResponse,
    ResultResponse,
)
from app.llm.client import LLMClient, get_llm_client
from app.core.gateway import GatewayError
from app.core.policy_engine import PolicyEngine, rule_id_for, validate_rule_pattern
from app.db.database import CoreDatabase, CoreDatabaseError, get_core_database
from app.db.models_core import CoreRecord, DefensiveRule
from app.db.security_store import SecurityDatabaseError
from app.security import record_event, scan_text

router = APIRouter()
logger = logging.getLogger(__name__)
REQUESTING_TENANT = "red-team"  # POST /attack bodies carry no tenant yet; the contract says red-team
DEFENDING_TENANT = "blue-team"


def _report_security(report, *args) -> None:
    """Record a security event; an audit problem must not hide the core result (/verify shows it)."""
    try:
        report(*args)
    except (SecurityDatabaseError, ValueError):
        logger.exception("security event was not recorded")


def _to_response(record: CoreRecord) -> CoreResponse:
    """Project a completed record into the public response (ids included)."""
    return CoreResponse(
        operation=record.operation,
        result=record.result,
        request_id=record.request_id,
        result_id=record.result_id,
    )


def _run_operation(
    operation: Operation,
    payload: CoreRequest,
    llm_client: LLMClient,
    database: CoreDatabase,
) -> CoreResponse | JSONResponse:
    try:
        decision = PolicyEngine(database).evaluate(payload.prompt)
    except CoreDatabaseError as exc:
        raise HTTPException(status_code=503, detail="Core persistence is unavailable") from exc
    logger.warning(
        "policy_decision operation=%s allowed=%s rule_id=%s",
        operation,
        decision.allowed,
        decision.rule_id,
    )
    if not decision.allowed:
        _report_security(
            record_event, REQUESTING_TENANT, "policy_block", {"operation": operation, "rule_id": decision.rule_id}
        )
        try:
            denied = database.save_record(
                operation=operation,
                prompt=payload.prompt,
                result=None,
                status="denied",
                rule_id=decision.rule_id,
            )
        except CoreDatabaseError as exc:
            raise HTTPException(status_code=503, detail="Core persistence is unavailable") from exc
        return JSONResponse(
            status_code=403,
            content=PolicyDenialResponse(
                code="policy_denied",
                message=decision.reason,
                rule_id=decision.rule_id,
                request_id=denied.request_id,
            ).model_dump(),
        )

    try:
        result = llm_client.generate(payload.prompt)
    except GatewayError as exc:
        try:
            database.save_record(
                operation=operation,
                prompt=payload.prompt,
                result=None,
                status="gateway_error",
            )
        except CoreDatabaseError as database_exc:
            raise HTTPException(status_code=503, detail="Core persistence is unavailable") from database_exc
        raise HTTPException(
            status_code=502,
            detail="LLM gateway is unavailable or returned an invalid response",
        ) from exc

    _report_security(scan_text, REQUESTING_TENANT, result)
    try:
        saved = database.save_record(
            operation=operation,
            prompt=payload.prompt,
            result=result,
            status="completed",
        )
    except CoreDatabaseError as exc:
        raise HTTPException(status_code=503, detail="Core persistence is unavailable") from exc
    return _to_response(saved)


@router.post(
    "/attack",
    response_model=CoreResponse,
    responses={403: {"model": PolicyDenialResponse, "description": "Request denied by the initial prompt policy."}},
    description="Submit an attack operation. Operation-specific semantics are not yet defined.",
)
def attack(
    payload: CoreRequest,
    llm_client: LLMClient = Depends(get_llm_client),
    database: CoreDatabase = Depends(get_core_database),
) -> CoreResponse:
    return _run_operation("attack", payload, llm_client, database)


@router.post(
    "/query",
    response_model=CoreResponse,
    responses={403: {"model": PolicyDenialResponse, "description": "Request denied by the initial prompt policy."}},
    description="Submit a query operation. Operation-specific semantics are not yet defined.",
)
def query(
    payload: CoreRequest,
    llm_client: LLMClient = Depends(get_llm_client),
    database: CoreDatabase = Depends(get_core_database),
) -> CoreResponse:
    return _run_operation("query", payload, llm_client, database)


def _save_defense_rule(payload: DefenseRuleRequest, database: CoreDatabase) -> DefenseRuleResponse:
    """Create or update a Blue Team rule; the policy engine applies it to the next request."""
    try:
        rule_id = rule_id_for(payload.name)
        validate_rule_pattern(payload.rule)
        database.save_defensive_rule(
            DefensiveRule(
                rule_id=rule_id,
                pattern=payload.rule,
                description=f"Denied by defense rule \u201c{payload.name}\u201d.",
                enabled=payload.enabled,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CoreDatabaseError as exc:
        raise HTTPException(status_code=503, detail="Core persistence is unavailable") from exc
    _report_security(
        record_event, DEFENDING_TENANT, "defense_rule_saved", {"rule_id": rule_id, "enabled": payload.enabled}
    )
    return DefenseRuleResponse(rule_id=rule_id, status="saved")


@router.post(
    "/defense",
    response_model=DefenseRuleResponse | CoreResponse,
    responses={403: {"model": PolicyDenialResponse, "description": "Prompt denied by the policy (prompt bodies only)."}},
    description=(
        "Blue Team: save or update a defensive rule with {name, rule, enabled}; the rule id is derived from the "
        "name. For backward compatibility a {prompt} body still runs the shared prompt operation."
    ),
)
def defense(
    payload: DefenseRuleRequest | CoreRequest,
    llm_client: LLMClient = Depends(get_llm_client),
    database: CoreDatabase = Depends(get_core_database),
) -> DefenseRuleResponse | CoreResponse | JSONResponse:
    if isinstance(payload, DefenseRuleRequest):
        return _save_defense_rule(payload, database)
    return _run_operation("defense", payload, llm_client, database)


@router.get(
    "/result",
    response_model=ResultResponse,
    responses={404: {"description": "No completed result has that result_id."}},
    description=(
        "Without a query, the latest completed result (or null). With ?result_id=, that exact completed result; "
        "an unknown id is a 404."
    ),
)
def get_result(
    result_id: str | None = Query(default=None, min_length=1, max_length=64),
    database: CoreDatabase = Depends(get_core_database),
) -> ResultResponse:
    try:
        if result_id is None:
            record = database.latest_completed_record()
        else:
            record = database.completed_record_by_result_id(result_id)
            if record is None:
                raise HTTPException(status_code=404, detail="Result not found")
    except CoreDatabaseError as exc:
        raise HTTPException(status_code=503, detail="Core persistence is unavailable") from exc
    result = _to_response(record) if record is not None and record.result is not None else None
    return ResultResponse(result=result)


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")