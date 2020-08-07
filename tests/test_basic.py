from pytest_httpx import HTTPXMock

import httpx_auth
from tests.auth_helper import get_header


def test_basic_authentication_send_authorization_header(httpx_mock: HTTPXMock):
    auth = httpx_auth.Basic("test_user", "test_pwd")
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Basic dGVzdF91c2VyOnRlc3RfcHdk"
    )
