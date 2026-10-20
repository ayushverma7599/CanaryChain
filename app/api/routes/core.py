import logging

from fastapi import APIRouter, Depends, HTTPException, Request
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

router = APIRouter()
logger = logging.getLogger(__name__)
policy_engine = PolicyEngine()


def _run_operation(
    operation: Operation,
    payload: CoreRequest,
    request: Request,
    llm_client: LLMClient,
) -> CoreResponse | JSONResponse:
    decision = policy_engine.evaluate(payload.prompt)
    logger.warning(
        "policy_decision operation=%s allowed=%s rule_id=%s",
        operation,
        decision.allowed,
        decision.rule_id,
    )
    if not decision.allowed:
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
        raise HTTPException(
            status_code=502,
            detail="LLM gateway is unavailable or returned an invalid response",
        ) from exc

    response = CoreResponse(operation=operation, result=result)
    request.app.state.latest_result = response
    return response


@router.post(
    "/attack",
    response_model=CoreResponse,
    responses={403: {"model": PolicyDenialResponse, "description": "Request denied by the initial prompt policy."}},
    description="Submit an attack operation. Operation-specific semantics are not yet defined.",
)
def attack(
    payload: CoreRequest,
    request: Request,
    llm_client: LLMClient = Depends(get_llm_client),
) -> CoreResponse:
    return _run_operation("attack", payload, request, llm_client)


@router.post(
    "/query",
    response_model=CoreResponse,
    responses={403: {"model": PolicyDenialResponse, "description": "Request denied by the initial prompt policy."}},
    description="Submit a query operation. Operation-specific semantics are not yet defined.",
)
def query(
    payload: CoreRequest,
    request: Request,
    llm_client: LLMClient = Depends(get_llm_client),
) -> CoreResponse:
    return _run_operation("query", payload, request, llm_client)


@router.post(
    "/defense",
    response_model=CoreResponse,
    responses={403: {"model": PolicyDenialResponse, "description": "Request denied by the initial prompt policy."}},
    description="Submit a defense operation. Operation-specific semantics are not yet defined.",
)
def defense(
    payload: CoreRequest,
    request: Request,
    llm_client: LLMClient = Depends(get_llm_client),
) -> CoreResponse:
    return _run_operation("defense", payload, request, llm_client)


@router.get("/result", response_model=ResultResponse)
def get_result(request: Request) -> ResultResponse:
    # TODO(next phase): persist results in the application database.
    return ResultResponse(result=getattr(request.app.state, "latest_result", None))


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")