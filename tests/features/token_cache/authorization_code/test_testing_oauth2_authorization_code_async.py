import httpx
import pytest
from pytest_httpx import HTTPXMock

import httpx_auth
from httpx_auth.testing import token_cache_mock


@pytest.fixture
def token_mock() -> str:
    return "2YotnFZFEjr1zCsicMWpAA"


@pytest.mark.asyncio
async def test_oauth2_authorization_code_flow(token_cache_mock, httpx_mock: HTTPXMock):
    auth = httpx_auth.OAuth2AuthorizationCode(
        "https://provide_code", "https://provide_access_token"
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )
    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)


@pytest.mark.asyncio
async def test_okta_authorization_code_flow(token_cache_mock, httpx_mock: HTTPXMock):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)


@pytest.mark.asyncio
async def test_oauth2_authorization_code_pkce_flow(
    token_cache_mock, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)


@pytest.mark.asyncio
async def test_okta_authorization_code_pkce_flow(
    token_cache_mock, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaAuthorizationCodePKCE(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)
