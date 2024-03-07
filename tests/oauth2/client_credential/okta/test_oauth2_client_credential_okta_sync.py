from pytest_httpx import HTTPXMock
import httpx

import httpx_auth
from httpx_auth.testing import token_cache
from httpx_auth._oauth2.tokens import to_expiry


def test_okta_client_credentials_flow_uses_provided_client(
    token_cache, httpx_mock: HTTPXMock
):
    headers = {"x-test": "Test value"}
    auth = httpx_auth.OktaClientCredentials(
        "test_okta",
        client_id="test_user",
        client_secret="test_pwd",
        scope="dummy",
        headers=headers,
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
        match_content=b"grant_type=client_credentials&scope=dummy",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_okta_client_credentials_flow_token_is_sent_in_authorization_header_by_default(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaClientCredentials(
        "test_okta", client_id="test_user", client_secret="test_pwd", scope="dummy"
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
        match_content=b"grant_type=client_credentials&scope=dummy",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_okta_client_credentials_flow_token_is_expired_after_30_seconds_by_default(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaClientCredentials(
        "test_okta", client_id="test_user", client_secret="test_pwd", scope="dummy"
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    token_cache._add_token(
        key="7830dd38bb95d4ac6273bd1a208c3db2097ac2715c6d3fb646ef3ccd48877109dd4cba292cef535559747cf6c4f497bf0804994dfb1c31bb293d2774889c2cfb",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=to_expiry(expires_in=29),
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
        match_content=b"grant_type=client_credentials&scope=dummy",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_okta_client_credentials_flow_token_custom_expiry(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaClientCredentials(
        "test_okta",
        client_id="test_user",
        client_secret="test_pwd",
        scope="dummy",
        early_expiry=28,
    )
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    token_cache._add_token(
        key="7830dd38bb95d4ac6273bd1a208c3db2097ac2715c6d3fb646ef3ccd48877109dd4cba292cef535559747cf6c4f497bf0804994dfb1c31bb293d2774889c2cfb",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=to_expiry(expires_in=29),
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_expires_in_sent_as_str(token_cache, httpx_mock: HTTPXMock):
    auth = httpx_auth.OktaClientCredentials(
        "test_okta", client_id="test_user", client_secret="test_pwd", scope="dummy"
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
        match_content=b"grant_type=client_credentials&scope=dummy",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)
