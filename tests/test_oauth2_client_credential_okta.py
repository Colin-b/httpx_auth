from pytest_httpx import HTTPXMock
import httpx

import httpx_auth
from tests.auth_helper import get_header
from httpx_auth.testing import token_cache


def test_okta_client_credentials_flow_uses_provided_client(
    token_cache, httpx_mock: HTTPXMock
):
    client = httpx.Client(headers={"x-test": "Test value"})
    auth = httpx_auth.OktaClientCredentials(
        "test_okta", client_id="test_user", client_secret="test_pwd", client=client
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
        match_headers={"x-test": "Test value"},
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )


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


def test_okta_client_credentials_flow_token_is_expired_after_30_seconds_by_default(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaClientCredentials(
        "test_okta", client_id="test_user", client_secret="test_pwd"
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    token_cache._add_token(
        key="f0d25aa4e496c6615328e776bb981dabe53fa77768a0a58eaf6d54215c598d80e57ffc7926fd96ec6a6a872942cb684a473e36233b593fb760d3eb6dc22ae550",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=httpx_auth.oauth2_tokens._to_expiry(expires_in=29),
    )
    # Meaning a new one will be requested
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


def test_okta_client_credentials_flow_token_custom_expiry(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaClientCredentials(
        "test_okta", client_id="test_user", client_secret="test_pwd", early_expiry=28
    )
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    token_cache._add_token(
        key="f0d25aa4e496c6615328e776bb981dabe53fa77768a0a58eaf6d54215c598d80e57ffc7926fd96ec6a6a872942cb684a473e36233b593fb760d3eb6dc22ae550",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=httpx_auth.oauth2_tokens._to_expiry(expires_in=29),
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
