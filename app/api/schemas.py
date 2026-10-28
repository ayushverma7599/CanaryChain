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


class DefenseRuleRequest(BaseModel):
    """Blue Team rule submission: a case-insensitive regular expression that denies matching prompts."""

    name: str = Field(min_length=1, max_length=80)
    rule: str = Field(min_length=1, max_length=200)
    enabled: bool = True

    @field_validator("name", "rule")
    @classmethod
    def must_contain_non_whitespace(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must contain non-whitespace characters")
        return value


class DefenseRuleResponse(BaseModel):
    rule_id: str
    status: Literal["saved"]


class CoreResponse(BaseModel):
    operation: Operation
    result: str
    request_id: str
    result_id: str


class PolicyDenialResponse(BaseModel):
    code: Literal["policy_denied"]
    message: str
    rule_id: str
    request_id: str


class ResultResponse(BaseModel):
    result: CoreResponse | None


class HealthResponse(BaseModel):
    status: Literal["ok"]