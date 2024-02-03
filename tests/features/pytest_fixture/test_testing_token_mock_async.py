import httpx
import pytest
from pytest_httpx import HTTPXMock

import httpx_auth
from httpx_auth.testing import token_cache_mock, token_mock


@pytest.mark.asyncio
async def test_token_mock(token_cache_mock, httpx_mock: HTTPXMock):
    auth = httpx_auth.OAuth2Implicit("https://provide_token")

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)
