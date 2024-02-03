import httpx
from pytest_httpx import HTTPXMock

import httpx_auth


def test_basic_authentication_send_authorization_header(httpx_mock: HTTPXMock):
    auth = httpx_auth.Basic("test_user", "test_pwd")

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Basic dGVzdF91c2VyOnRlc3RfcHdk",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)
