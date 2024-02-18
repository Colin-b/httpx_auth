from pytest_httpx import HTTPXMock
import pytest
import httpx

import httpx_auth
from httpx_auth.testing import BrowserMock, browser_mock, token_cache
from httpx_auth._oauth2.tokens import to_expiry


@pytest.mark.asyncio
async def test_oauth2_authorization_code_flow_uses_provided_client(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    client = httpx.Client(headers={"x-test": "Test value"})
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com",
        "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
        client=client,
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
        match_headers={"x-test": "Test value"},
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

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_authorization_code_flow_uses_redirect_uri_domain(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com",
        "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
        redirect_uri_domain="localhost.mycompany.com",
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost.mycompany.com%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost.mycompany.com%3A5000%2F&client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
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

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_authorization_code_flow_uses_custom_success(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com",
        "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
    )
    httpx_auth.OAuth2.display.success_html = (
        "<body><div>SUCCESS: {display_time}</div></body>"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
        displayed_html="<body><div>SUCCESS: {display_time}</div></body>",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
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

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_authorization_code_flow_uses_custom_failure(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com",
        "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
    )
    httpx_auth.OAuth2.display.failure_html = "FAILURE: {display_time}\n{information}"
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_request",
        displayed_html="FAILURE: {display_time}\n{information}",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest):
            await client.get("https://authorized_only", auth=auth)

    tab.assert_failure(
        "invalid_request: The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."
    )


@pytest.mark.asyncio
async def test_oauth2_authorization_code_flow_get_code_is_sent_in_authorization_header_by_default(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
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

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_authorization_code_flow_get_code_is_expired_after_30_seconds_by_default(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    token_cache._add_token(
        key="5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=to_expiry(expires_in=29),
    )
    # Meaning a new one will be requested
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
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

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_authorization_code_flow_get_code_custom_expiry(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com",
        "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
        early_expiry=28,
    )
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    token_cache._add_token(
        key="5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
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
async def test_oauth2_authorization_code_flow_refresh_token(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": "0",
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
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

    tab.assert_success()

    # response for refresh token grant
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "rVR7Syg5bjZtZYjbZIW",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=refresh_token&client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer rVR7Syg5bjZtZYjbZIW",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)


@pytest.mark.asyncio
async def test_oauth2_authorization_code_flow_refresh_token_invalid(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": "0",
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
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

    tab.assert_success()

    # response for refresh token grant
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_request"},
        status_code=400,
        match_content=b"grant_type=refresh_token&client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA",
    )

    # initialize tab again because a thread can only be started once
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
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

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_authorization_code_flow_refresh_token_access_token_not_expired(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
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

    tab.assert_success()

    # expect Bearer token to remain the same
    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)


@pytest.mark.asyncio
async def test_empty_token_is_invalid(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.GrantNotProvided) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "access_token not provided within {'access_token': '', 'token_type': 'example', 'expires_in': 3600, 'refresh_token': 'tGzv3JOkF0XG5Qx2TlKWIA', 'example_parameter': 'example_value'}."
    )
    tab.assert_success()


@pytest.mark.asyncio
async def test_with_invalid_grant_request_no_json(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        text="failure",
        status_code=400,
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest, match="failure"):
            await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_with_invalid_grant_request_invalid_request_error(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_request"},
        status_code=400,
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "invalid_request: The request is missing a required parameter, includes an "
        "unsupported parameter value (other than grant type), repeats a parameter, "
        "includes multiple credentials, utilizes more than one mechanism for "
        "authenticating the client, or is otherwise malformed."
    )
    tab.assert_success()


@pytest.mark.asyncio
async def test_with_invalid_grant_request_invalid_request_error_and_error_description(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_request", "error_description": "desc of the error"},
        status_code=400,
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert str(exception_info.value) == "invalid_request: desc of the error"
    tab.assert_success()


@pytest.mark.asyncio
async def test_with_invalid_grant_request_invalid_request_error_and_error_description_and_uri(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "error": "invalid_request",
            "error_description": "desc of the error",
            "error_uri": "https://test_url",
        },
        status_code=400,
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == f"invalid_request: desc of the error\nMore information can be found on https://test_url"
    )
    tab.assert_success()


@pytest.mark.asyncio
async def test_with_invalid_grant_request_invalid_request_error_and_error_description_and_uri_and_other_fields(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "error": "invalid_request",
            "error_description": "desc of the error",
            "error_uri": "https://test_url",
            "other": "other info",
        },
        status_code=400,
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "invalid_request: desc of the error\nMore information can be found on https://test_url\nAdditional information: {'other': 'other info'}"
    )
    tab.assert_success()


@pytest.mark.asyncio
async def test_with_invalid_grant_request_without_error(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"other": "other info"},
        status_code=400,
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(
            httpx_auth.InvalidGrantRequest, match="{'other': 'other info'}"
        ):
            await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_with_invalid_grant_request_invalid_client_error(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_client"},
        status_code=400,
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "invalid_client: Client authentication failed (e.g., unknown client, no "
        "client authentication included, or unsupported authentication method).  The "
        "authorization server MAY return an HTTP 401 (Unauthorized) status code to "
        "indicate which HTTP authentication schemes are supported.  If the client "
        'attempted to authenticate via the "Authorization" request header field, the '
        "authorization server MUST respond with an HTTP 401 (Unauthorized) status "
        'code and include the "WWW-Authenticate" response header field matching the '
        "authentication scheme used by the client."
    )
    tab.assert_success()


@pytest.mark.asyncio
async def test_with_invalid_grant_request_invalid_grant_error(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_grant"},
        status_code=400,
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "invalid_grant: The provided authorization grant (e.g., authorization code, "
        "resource owner credentials) or refresh token is invalid, expired, revoked, "
        "does not match the redirection URI used in the authorization request, or was "
        "issued to another client."
    )
    tab.assert_success()


@pytest.mark.asyncio
async def test_with_invalid_grant_request_unauthorized_client_error(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "unauthorized_client"},
        status_code=400,
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "unauthorized_client: The authenticated client is not authorized to use this "
        "authorization grant type."
    )
    tab.assert_success()


@pytest.mark.asyncio
async def test_with_invalid_grant_request_unsupported_grant_type_error(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "unsupported_grant_type"},
        status_code=400,
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "unsupported_grant_type: The authorization grant type is not supported by the "
        "authorization server."
    )
    tab.assert_success()


@pytest.mark.asyncio
async def test_with_invalid_grant_request_invalid_scope_error(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_scope"},
        status_code=400,
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "invalid_scope: The requested scope is invalid, unknown, malformed, or "
        "exceeds the scope granted by the resource owner."
    )
    tab.assert_success()


@pytest.mark.asyncio
async def test_with_invalid_token_request_invalid_request_error(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_request",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "invalid_request: The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."
    )
    tab.assert_failure(
        "invalid_request: The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."
    )


@pytest.mark.asyncio
async def test_with_invalid_token_request_invalid_request_error_and_error_description(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_request&error_description=desc",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(
            httpx_auth.InvalidGrantRequest, match="invalid_request: desc"
        ):
            await client.get("https://authorized_only", auth=auth)

    tab.assert_failure("invalid_request: desc")


@pytest.mark.asyncio
async def test_with_invalid_token_request_invalid_request_error_and_error_description_and_uri(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_request&error_description=desc&error_uri=https://test_url",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "invalid_request: desc\nMore information can be found on https://test_url"
    )
    tab.assert_failure(
        "invalid_request: desc<br>More information can be found on https://test_url"
    )


@pytest.mark.asyncio
async def test_with_invalid_token_request_invalid_request_error_and_error_description_and_uri_and_other_fields(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_request&error_description=desc&error_uri=https://test_url&other=test",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "invalid_request: desc\nMore information can be found on https://test_url\nAdditional information: {'other': ['test']}"
    )
    tab.assert_failure(
        "invalid_request: desc<br>More information can be found on https://test_url<br>Additional information: {'other': ['test']}"
    )


@pytest.mark.asyncio
async def test_with_invalid_token_request_unauthorized_client_error(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=unauthorized_client",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "unauthorized_client: The client is not authorized to request an authorization code or an access token using this method."
    )
    tab.assert_failure(
        "unauthorized_client: The client is not authorized to request an authorization code or an access token using this method."
    )


@pytest.mark.asyncio
async def test_with_invalid_token_request_access_denied_error(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=access_denied",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "access_denied: The resource owner or authorization server denied the request."
    )
    tab.assert_failure(
        "access_denied: The resource owner or authorization server denied the request."
    )


@pytest.mark.asyncio
async def test_with_invalid_token_request_unsupported_response_type_error(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=unsupported_response_type",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "unsupported_response_type: The authorization server does not support obtaining an authorization code or an access token using this method."
    )
    tab.assert_failure(
        "unsupported_response_type: The authorization server does not support obtaining an authorization code or an access token using this method."
    )


@pytest.mark.asyncio
async def test_with_invalid_token_request_invalid_scope_error(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_scope",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "invalid_scope: The requested scope is invalid, unknown, or malformed."
    )
    tab.assert_failure(
        "invalid_scope: The requested scope is invalid, unknown, or malformed."
    )


@pytest.mark.asyncio
async def test_with_invalid_token_request_server_error_error(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=server_error",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "server_error: The authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )
    tab.assert_failure(
        "server_error: The authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )


@pytest.mark.asyncio
async def test_with_invalid_token_request_temporarily_unavailable_error(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.OktaAuthorizationCode(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    tab = browser_mock.add_response(
        opened_url="https://testserver.okta-emea.com/oauth2/default/v1/authorize?client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd&scope=openid&response_type=code&state=5264d11c8b268ccf911ce564ca42fd75cea68c4a3c1ec3ac1ab20243891ab7cd5250ad4c2d002017c6e8ac2ba34954293baa5e0e4fd00bb9ffd4a39c45f1960b&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=temporarily_unavailable",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "temporarily_unavailable: The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.  (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )
    tab.assert_failure(
        "temporarily_unavailable: The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.  (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )
