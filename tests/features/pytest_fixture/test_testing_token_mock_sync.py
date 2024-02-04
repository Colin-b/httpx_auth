import httpx
from pytest_httpx import HTTPXMock

import httpx_auth
from httpx_auth.testing import token_cache_mock, token_mock


def test_token_mock(token_cache_mock, httpx_mock: HTTPXMock):
    auth = httpx_auth.OAuth2Implicit("https://provide_token")

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)
