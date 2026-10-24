from typing import Literal

from pydantic import BaseModel, Field, field_validator

Operation = Literal["attack", "query", "defense"]


class CoreRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=8000)

    @field_validator("prompt")
    @classmethod
    def prompt_must_contain_non_whitespace(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("prompt must contain non-whitespace characters")
        return value


class CoreResponse(BaseModel):
    operation: Operation
    result: str


class PolicyDenialResponse(BaseModel):
    code: Literal["policy_denied"]
    message: str
    rule_id: str


class ResultResponse(BaseModel):
    result: CoreResponse | None


class HealthResponse(BaseModel):
    status: Literal["ok"]