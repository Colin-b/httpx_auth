from pytest_httpx import HTTPXMock

import httpx_auth
from httpx_auth.testing import token_cache_mock, token_mock
from tests.auth_helper import get_header


def test_token_mock(token_cache_mock, httpx_mock: HTTPXMock):
    auth = httpx_auth.OAuth2Implicit("https://provide_token")
    expected_token = httpx_auth.OAuth2.token_cache.get_token("")
    assert (
        get_header(httpx_mock, auth).get("Authorization") == f"Bearer {expected_token}"
    )
