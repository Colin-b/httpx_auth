import json
import time
import datetime
import typing

import httpx
import jwt
import pytest
from pytest_asyncio.plugin import unused_tcp_port
from pytest_httpx import HTTPXMock

from httpx_auth.testing import BrowserMock, create_token, token_cache, browser_mock
import httpx_auth
from httpx_auth._oauth2.tokens import to_expiry


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_token_is_not_reused_if_a_url_parameter_is_changing(
    token_cache,
    httpx_mock: HTTPXMock,
    browser_mock: BrowserMock,
    unused_tcp_port_factory: typing.Callable[[], int],
):
    auth1 = httpx_auth.OAuth2Implicit(
        "https://provide_token?response_type=custom_token&fake_param=1",
        token_field_name="custom_token",
        redirect_uri_port=unused_tcp_port_factory(),
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    first_token = create_token(expiry_in_1_hour)
    tab1 = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=custom_token&fake_param=1&state=fc65632abc93fbf8fede279fb6405912f18e05e5e7042b9d92e711f341b8a71efede90865c5fb38f0f11735e9923c0dccdf173be81acf61955f873d4a6e28fdb&redirect_uri=http%3A%2F%2Flocalhost%3A{auth1.redirect_uri_port}%2F",
        reply_url=f"http://localhost:{auth1.redirect_uri_port}",
        data=f"custom_token={first_token}&state=fc65632abc93fbf8fede279fb6405912f18e05e5e7042b9d92e711f341b8a71efede90865c5fb38f0f11735e9923c0dccdf173be81acf61955f873d4a6e28fdb",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {first_token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth1)

    # Ensure that the new token is different than previous one
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1, seconds=1)

    auth2 = httpx_auth.OAuth2Implicit(
        "https://provide_token?response_type=custom_token&fake_param=2",
        token_field_name="custom_token",
        redirect_uri_port=unused_tcp_port_factory(),
    )
    second_token = create_token(expiry_in_1_hour)
    tab2 = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=custom_token&fake_param=2&state=91db107a8c3b8043302186936dd11ecc35049dc78b28d3642a62ba350e0a3e3b673d98b2820226bee5f3eca9633bd61825253cc7efe641bf9ad81bdae4d7adc9&redirect_uri=http%3A%2F%2Flocalhost%3A{auth2.redirect_uri_port}%2F",
        reply_url=f"http://localhost:{auth2.redirect_uri_port}",
        data=f"custom_token={second_token}&state=91db107a8c3b8043302186936dd11ecc35049dc78b28d3642a62ba350e0a3e3b673d98b2820226bee5f3eca9633bd61825253cc7efe641bf9ad81bdae4d7adc9",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {second_token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth2)

    tab1.assert_success()
    tab2.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_uses_redirect_uri_domain(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token",
        redirect_uri_domain="localhost.mycompany.com",
        redirect_uri_port=unused_tcp_port,
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost.mycompany.com%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"access_token={token}&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_uses_custom_success(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token",
        redirect_uri_port=unused_tcp_port,
    )
    httpx_auth.OAuth2.display.success_html = (
        "<body><div>SUCCESS: {display_time}</div></body>"
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        displayed_html="<body><div>SUCCESS: {display_time}</div></body>",
        data=f"access_token={token}&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_uses_custom_failure(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token",
        redirect_uri_port=unused_tcp_port,
    )
    httpx_auth.OAuth2.display.failure_html = "FAILURE: {display_time}\n{information}"
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}#error=invalid_request",
        displayed_html="FAILURE: {display_time}\n{information}",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest):
            await client.get("https://authorized_only", auth=auth)

    tab.assert_failure(
        "invalid_request: The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."
    )


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_token_is_reused_if_only_nonce_differs(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth1 = httpx_auth.OAuth2Implicit(
        "https://provide_token?response_type=custom_token&nonce=1",
        token_field_name="custom_token",
        redirect_uri_port=unused_tcp_port,
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=custom_token&state=da5ed86c8443102b3d318731e35c51a9d7d3fc8ab5ccfc138531399803c4d8f72268347e85db8b8953c8d5c97039af70f924fd0cb075e0c5876f7502d4e8ff79&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F&nonce=%5B%271%27%5D",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"custom_token={token}&state=da5ed86c8443102b3d318731e35c51a9d7d3fc8ab5ccfc138531399803c4d8f72268347e85db8b8953c8d5c97039af70f924fd0cb075e0c5876f7502d4e8ff79",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth1)

    auth2 = httpx_auth.OAuth2Implicit(
        "https://provide_token?response_type=custom_token&nonce=2",
        token_field_name="custom_token",
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )
    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth2)

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_token_can_be_requested_on_a_custom_server_port(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"access_token={token}&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_post_token_is_sent_in_authorization_header_by_default(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = jwt.encode(
        {
            "exp": expiry_in_1_hour,
            "data": json.dumps({"something 漢字": ["漢字 else"]}),
        },
        "secret",
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"access_token={token}&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_post_token_is_expired_after_30_seconds_by_default(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    expiry_in_29_seconds = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(seconds=29)
    token_cache._add_token(
        key="bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
        token=create_token(expiry_in_29_seconds),
        expiry=to_expiry(expires_in=29),
    )
    # Meaning a new one will be requested
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"access_token={token}&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_post_token_custom_expiry(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit("https://provide_token", early_expiry=28)
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    expiry_in_29_seconds = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(seconds=29)
    token = create_token(expiry_in_29_seconds)
    token_cache._add_token(
        key="bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
        token=create_token(expiry_in_29_seconds),
        expiry=to_expiry(expires_in=29),
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)


@pytest.mark.asyncio
async def test_browser_opening_failure(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, unused_tcp_port: int
):
    import httpx_auth._oauth2.authentication_responses_server

    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", timeout=0.1, redirect_uri_port=unused_tcp_port
    )

    class FakeBrowser:
        def open(self, url, new):
            return False

    monkeypatch.setattr(
        httpx_auth._oauth2.authentication_responses_server.webbrowser,
        "get",
        lambda *args: FakeBrowser(),
    )

    httpx_mock.add_response(
        method="GET",
        url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.TimeoutOccurred) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "User authentication was not received within 0.1 seconds."
    )


@pytest.mark.asyncio
async def test_browser_error(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, unused_tcp_port: int
):
    import httpx_auth._oauth2.authentication_responses_server

    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", timeout=0.1, redirect_uri_port=unused_tcp_port
    )

    class FakeBrowser:
        def open(self, url, new):
            import webbrowser

            raise webbrowser.Error("Failure")

    monkeypatch.setattr(
        httpx_auth._oauth2.authentication_responses_server.webbrowser,
        "get",
        lambda *args: FakeBrowser(),
    )

    httpx_mock.add_response(
        method="GET",
        url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
    )
    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.TimeoutOccurred) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "User authentication was not received within 0.1 seconds."
    )


@pytest.mark.asyncio
async def test_state_change(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"access_token={token}&state=123456",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_empty_token_is_invalid(
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"access_token=&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidToken, match=" is invalid."):
            await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_token_without_expiry_is_invalid(
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"access_token={create_token(None)}&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.TokenExpiryNotProvided) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert str(exception_info.value) == "Expiry (exp) is not provided in None."
    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_get_token_is_sent_in_authorization_header_by_default(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}#access_token={token}&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_token_is_sent_in_requested_field(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token",
        header_name="Bearer",
        header_value="{token}",
        redirect_uri_port=unused_tcp_port,
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"access_token={token}&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Bearer": token,
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_can_send_a_custom_response_type_and_expects_token_to_be_received_with_this_name(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token",
        response_type="custom_token",
        token_field_name="custom_token",
        redirect_uri_port=unused_tcp_port,
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=custom_token&state=da5ed86c8443102b3d318731e35c51a9d7d3fc8ab5ccfc138531399803c4d8f72268347e85db8b8953c8d5c97039af70f924fd0cb075e0c5876f7502d4e8ff79&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"custom_token={token}&state=da5ed86c8443102b3d318731e35c51a9d7d3fc8ab5ccfc138531399803c4d8f72268347e85db8b8953c8d5c97039af70f924fd0cb075e0c5876f7502d4e8ff79",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_expects_token_in_id_token_if_response_type_is_id_token(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token",
        response_type="id_token",
        redirect_uri_port=unused_tcp_port,
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=id_token&state=4b7a43e14ff4940a513dba46a736b62890e0a568f3342412cecfa968af823feae7b3c56cd2ecf07d533df3990cdc7436b3c090f27e6fde42813a3c6510e077d9&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"id_token={token}&state=4b7a43e14ff4940a513dba46a736b62890e0a568f3342412cecfa968af823feae7b3c56cd2ecf07d533df3990cdc7436b3c090f27e6fde42813a3c6510e077d9",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_expects_token_in_id_token_if_response_type_in_url_is_id_token(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token?response_type=id_token",
        redirect_uri_port=unused_tcp_port,
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=id_token&state=4b7a43e14ff4940a513dba46a736b62890e0a568f3342412cecfa968af823feae7b3c56cd2ecf07d533df3990cdc7436b3c090f27e6fde42813a3c6510e077d9&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"id_token={token}&state=4b7a43e14ff4940a513dba46a736b62890e0a568f3342412cecfa968af823feae7b3c56cd2ecf07d533df3990cdc7436b3c090f27e6fde42813a3c6510e077d9",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_expects_token_to_be_stored_in_access_token_by_default(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"access_token={token}&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_token_is_reused_if_not_expired(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth1 = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"access_token={token}&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth1)

    auth2 = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {token}",
        },
    )
    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth2)

    tab.assert_success()


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_post_failure_if_token_is_not_provided(
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data="",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(Exception) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert str(exception_info.value) == "access_token not provided within {}."
    tab.assert_failure("access_token not provided within {}.")


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_get_failure_if_token_is_not_provided(
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(Exception) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert str(exception_info.value) == "access_token not provided within {}."
    tab.assert_failure("access_token not provided within {}.")


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_post_failure_if_state_is_not_provided(
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"access_token={token}",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.StateNotProvided) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == f"state not provided within {{'access_token': ['{token}']}}."
    )
    tab.assert_failure(f"state not provided within {{'access_token': ['{token}']}}.")


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_get_failure_if_state_is_not_provided(
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = create_token(expiry_in_1_hour)
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}#access_token={token}",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.StateNotProvided) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == f"state not provided within {{'access_token': ['{token}'], 'httpx_auth_redirect': ['1']}}."
    )
    tab.assert_failure(
        f"state not provided within {{'access_token': ['{token}'], 'httpx_auth_redirect': ['1']}}."
    )


@pytest.mark.asyncio
async def test_with_invalid_token_request_invalid_request_error(
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}#error=invalid_request",
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
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}#error=invalid_request&error_description=desc",
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert str(exception_info.value) == "invalid_request: desc"
    tab.assert_failure("invalid_request: desc")


@pytest.mark.asyncio
async def test_with_invalid_token_request_invalid_request_error_and_error_description_and_uri(
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}#error=invalid_request&error_description=desc&error_uri=https://test_url",
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
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}#error=invalid_request&error_description=desc&error_uri=https://test_url&other=test",
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
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}#error=unauthorized_client",
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
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}#error=access_denied",
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
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}#error=unsupported_response_type",
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
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}#error=invalid_scope",
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
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}#error=server_error",
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
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    tab = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}#error=temporarily_unavailable",
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


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_failure_if_token_is_not_received_within_the_timeout_interval(
    token_cache, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", timeout=0.1, redirect_uri_port=unused_tcp_port
    )
    browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        # Simulate no redirect
        reply_url=None,
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx_auth.TimeoutOccurred) as exception_info:
            await client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "User authentication was not received within 0.1 seconds."
    )


@pytest.mark.asyncio
async def test_oauth2_implicit_flow_token_is_requested_again_if_expired(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock, unused_tcp_port: int
):
    auth = httpx_auth.OAuth2Implicit(
        "https://provide_token", redirect_uri_port=unused_tcp_port
    )
    # This token will expires in 100 milliseconds
    expiry_in_1_second = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(milliseconds=100)
    first_token = create_token(expiry_in_1_second)
    tab1 = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"access_token={first_token}&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {first_token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)

    # Wait to ensure that the token will be considered as expired
    time.sleep(0.2)

    # Token should now be expired, a new one should be requested
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    second_token = create_token(expiry_in_1_hour)
    tab2 = browser_mock.add_response(
        opened_url=f"https://provide_token?response_type=token&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c&redirect_uri=http%3A%2F%2Flocalhost%3A{unused_tcp_port}%2F",
        reply_url=f"http://localhost:{unused_tcp_port}",
        data=f"access_token={second_token}&state=bee505cb6ceb14b9f6ac3573cd700b3b3e965004078d7bb57c7b92df01e448c992a7a46b4804164fc998ea166ece3f3d5849ca2405c4a548f43b915b0677231c",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": f"Bearer {second_token}",
        },
    )

    async with httpx.AsyncClient() as client:
        await client.get("https://authorized_only", auth=auth)

    tab1.assert_success()
    tab2.assert_success()
