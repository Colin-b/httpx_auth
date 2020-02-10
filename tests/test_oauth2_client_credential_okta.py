from pytest_httpx import httpx_mock, HTTPXMock

import httpx_auth
from tests.auth_helper import get_header
from httpx_auth.testing import token_cache


def test_okta_client_credentials_flow_token_is_sent_in_authorization_header_by_default(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaClientCredentials(
        "test_okta", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://test_okta/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )


def test_expires_in_sent_as_str(token_cache, httpx_mock: HTTPXMock):
    auth = httpx_auth.OktaClientCredentials(
        "test_okta", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://test_okta/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": "3600",
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )
