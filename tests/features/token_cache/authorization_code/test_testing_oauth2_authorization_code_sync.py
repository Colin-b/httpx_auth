import pytest
from pytest_httpx import HTTPXMock

import httpx_auth
from httpx_auth.testing import token_cache_mock
from tests.auth_helper import get_header


@pytest.fixture
def token_mock() -> str:
    return "2YotnFZFEjr1zCsicMWpAA"


def test_oauth2_authorization_code_flow(token_cache_mock, httpx_mock: HTTPXMock):
    auth = httpx_auth.OAuth2AuthorizationCode(
        "https://provide_code", "https://provide_access_token"
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )


def test_okta_authorization_code_flow(token_cache_mock, httpx_mock: HTTPXMock):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )


def test_oauth2_authorization_code_pkce_flow(token_cache_mock, httpx_mock: HTTPXMock):
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )


def test_okta_authorization_code_pkce_flow(token_cache_mock, httpx_mock: HTTPXMock):
    auth = httpx_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )
