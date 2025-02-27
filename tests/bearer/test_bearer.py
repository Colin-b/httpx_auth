from pytest_httpx import HTTPXMock
import httpx
import pytest

import httpx_auth


def test_bearer_requires_atoken():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.BearerToken(None)
    assert str(exception_info.value) == "Token is mandatory."

def test_bearer_token_is_sent(httpx_mock: HTTPXMock):
    auth = httpx_auth.BearerToken("my_token")

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={"Authorization": "Bearer my_token"},
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)
