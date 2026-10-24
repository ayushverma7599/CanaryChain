import httpx
import pytest

from app.core.gateway import GatewayClient, GatewayError


def test_chat_uses_existing_gateway_route_without_claiming_identity() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"reply": "stub response"})

    client = GatewayClient(
        base_url="http://gateway:8080",
        transport=httpx.MockTransport(handler),
    )
    try:
        assert client.chat("check this prompt") == "stub response"
    finally:
        client.close()

    assert len(requests) == 1
    assert requests[0].method == "POST"
    assert requests[0].url == "http://gateway:8080/llm/v1/chat"
    assert requests[0].read() == b'{"prompt":"check this prompt"}'
    assert "x-tenant" not in requests[0].headers


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(503, json={"error": "unavailable"}),
        httpx.Response(200, json={"unexpected": "shape"}),
        httpx.Response(200, content=b"not-json"),
    ],
)
def test_chat_converts_upstream_failures_to_gateway_error(response: httpx.Response) -> None:
    client = GatewayClient(transport=httpx.MockTransport(lambda _request: response))
    try:
        with pytest.raises(GatewayError):
            client.chat("prompt")
    finally:
        client.close()