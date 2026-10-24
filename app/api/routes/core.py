import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from app.api.schemas import (
    CoreRequest,
    CoreResponse,
    HealthResponse,
    Operation,
    PolicyDenialResponse,
    ResultResponse,
)
from app.llm.client import LLMClient, get_llm_client
from app.core.gateway import GatewayError
from app.core.policy_engine import PolicyEngine
from app.db.database import CoreDatabase, CoreDatabaseError, get_core_database
from app.db.security_store import SecurityDatabaseError
from app.security import record_event, scan_text

router = APIRouter()
logger = logging.getLogger(__name__)
REQUESTING_TENANT = "red-team"  # POST /attack bodies carry no tenant yet; the contract says red-team


def _report_security(report, *args) -> None:
    """Record a security event; an audit problem must not hide the core result (/verify shows it)."""
    try:
        report(*args)
    except (SecurityDatabaseError, ValueError):
        logger.exception("security event was not recorded")


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
            database.save_record(
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
    response = CoreResponse(operation=operation, result=result)
    try:
        database.save_record(
            operation=operation,
            prompt=payload.prompt,
            result=result,
            status="completed",
        )
    except CoreDatabaseError as exc:
        raise HTTPException(status_code=503, detail="Core persistence is unavailable") from exc
    return response


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


@router.post(
    "/defense",
    response_model=CoreResponse,
    responses={403: {"model": PolicyDenialResponse, "description": "Request denied by the initial prompt policy."}},
    description="Submit a defense operation. Operation-specific semantics are not yet defined.",
)
def defense(
    payload: CoreRequest,
    llm_client: LLMClient = Depends(get_llm_client),
    database: CoreDatabase = Depends(get_core_database),
) -> CoreResponse:
    return _run_operation("defense", payload, llm_client, database)


@router.get("/result", response_model=ResultResponse)
def get_result(database: CoreDatabase = Depends(get_core_database)) -> ResultResponse:
    try:
        record = database.latest_completed_record()
    except CoreDatabaseError as exc:
        raise HTTPException(status_code=503, detail="Core persistence is unavailable") from exc
    result = (
        CoreResponse(operation=record.operation, result=record.result)
        if record is not None and record.result is not None
        else None
    )
    return ResultResponse(result=result)


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")