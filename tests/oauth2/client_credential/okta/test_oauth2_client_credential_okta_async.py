import pytest
from pytest_httpx import HTTPXMock
import httpx

import httpx_auth
from httpx_auth.testing import token_cache
from httpx_auth._oauth2.tokens import to_expiry


@pytest.mark.asyncio
async def test_okta_client_credentials_flow_uses_provided_client(
    token_cache, httpx_mock: HTTPXMock
):
    # TODO Add support for AsyncClient
    client = httpx.Client(headers={"x-test": "Test value"})
    auth = httpx_auth.OktaClientCredentials(
        "test_okta",
        client_id="test_user",
        client_secret="test_pwd",
        scope="dummy",
        client=client,
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

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)


@pytest.mark.asyncio
async def test_okta_client_credentials_flow_token_is_sent_in_authorization_header_by_default(
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

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)


@pytest.mark.asyncio
async def test_okta_client_credentials_flow_token_is_expired_after_30_seconds_by_default(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaClientCredentials(
        "test_okta", client_id="test_user", client_secret="test_pwd", scope="dummy"
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    token_cache._add_token(
        key="73cb07a6e48774ad335f5bae75e036d1df813a3c44ae186895eb6f956b9993ed83590871dddefbc2310b863cda3f414161bc7fcd4c4e5fefa582cba4f7de7ace",
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

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)


@pytest.mark.asyncio
async def test_okta_client_credentials_flow_token_custom_expiry(
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
        key="73cb07a6e48774ad335f5bae75e036d1df813a3c44ae186895eb6f956b9993ed83590871dddefbc2310b863cda3f414161bc7fcd4c4e5fefa582cba4f7de7ace",
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

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)


@pytest.mark.asyncio
async def test_expires_in_sent_as_str(token_cache, httpx_mock: HTTPXMock):
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

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)


@pytest.mark.parametrize(
    "client_id1, client_secret1, client_id2, client_secret2",
    [
        # Use the same client secret but for different client ids (different application)
        ("user1", "test_pwd", "user2", "test_pwd"),
        # Use the same client id but with different client secrets (update of secret)
        ("test_user", "old_pwd", "test_user", "new_pwd"),
    ],
)
@pytest.mark.asyncio
async def test_handle_credentials_as_part_of_cache_key(
    token_cache,
    httpx_mock: HTTPXMock,
    client_id1,
    client_secret1,
    client_id2,
    client_secret2,
):
    auth1 = httpx_auth.OktaClientCredentials(
        "test_okta", client_id=client_id1, client_secret=client_secret1, scope="dummy"
    )
    auth2 = httpx_auth.OktaClientCredentials(
        "test_okta", client_id=client_id2, client_secret=client_secret2, scope="dummy"
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

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth1)

    httpx_mock.add_response(
        method="POST",
        url="https://test_okta/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAB",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIB",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=client_credentials&scope=dummy",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAB",
        },
    )

    # This should request a new token (different credentials)
    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth2)

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAB",
        },
    )
    # Ensure the proper token is fetched
    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth1)
        await client.get("https://authorized_only", auth=auth2)
