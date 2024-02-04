import httpx
import pytest
from pytest_httpx import HTTPXMock

import httpx_auth
from httpx_auth.testing import token_cache_mock


@pytest.fixture
def token_mock() -> str:
    return "2YotnFZFEjr1zCsicMWpAA"


def test_oauth2_implicit_flow(token_cache_mock, httpx_mock: HTTPXMock):
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


def test_okta_implicit_flow(token_cache_mock, httpx_mock: HTTPXMock):
    auth = httpx_auth.OktaImplicit(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
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


def test_aad_implicit_flow(token_cache_mock, httpx_mock: HTTPXMock):
    auth = httpx_auth.AzureActiveDirectoryImplicit(
        "45239d18-c68c-4c47-8bdd-ce71ea1d50cd", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
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


def test_okta_implicit_id_token_flow(token_cache_mock, httpx_mock: HTTPXMock):
    auth = httpx_auth.OktaImplicitIdToken(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
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


def test_aad_implicit_id_token_flow(token_cache_mock, httpx_mock: HTTPXMock):
    auth = httpx_auth.AzureActiveDirectoryImplicitIdToken(
        "45239d18-c68c-4c47-8bdd-ce71ea1d50cd", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
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
