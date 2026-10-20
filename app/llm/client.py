from functools import lru_cache

from app.core.gateway import GatewayClient


class LLMClient:
    """Expose the existing stub LLM through the security gateway adapter."""

    def __init__(self, gateway: GatewayClient) -> None:
        self._gateway = gateway

    def generate(self, prompt: str) -> str:
        return self._gateway.chat(prompt)


@lru_cache(maxsize=1)
def get_llm_client() -> LLMClient:
    return LLMClient(GatewayClient())