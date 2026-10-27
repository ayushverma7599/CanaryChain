import os
from typing import Any

import httpx


class GatewayError(RuntimeError):
    """Raised when the existing gateway cannot serve a valid LLM response."""


class GatewayClient:
    """HTTP client for the existing security gateway; this is not a proxy."""

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._client = httpx.Client(
            base_url=(base_url or os.environ.get("GATEWAY_BASE_URL", "http://127.0.0.1:8080")).rstrip("/"),
            timeout=timeout,
            transport=transport,
        )

    def chat(self, prompt: str) -> str:
        try:
            response = self._client.post("/llm/v1/chat", json={"prompt": prompt})
            response.raise_for_status()
            body: Any = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise GatewayError("gateway request failed") from exc

        if not isinstance(body, dict) or not isinstance(body.get("reply"), str):
            raise GatewayError("gateway returned an invalid LLM response")
        return body["reply"]

    def close(self) -> None:
        self._client.close()