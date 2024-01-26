from pytest_httpx import HTTPXMock
import pytest
import httpx

import httpx_auth
from httpx_auth.testing import BrowserMock, browser_mock, token_cache
from tests.auth_helper import get_header


def test_oauth2_authorization_code_flow_uses_provided_client(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    client = httpx.Client(headers={"x-test": "Test value"})
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
        client=client,
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        html="access_token=waka_tok_12345&token_type=bearer&expires_in=3600&refresh_token=waka_ref_12345&scope=email&example_parameter=example_value",
        match_content=b"grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
        match_headers={"x-test": "Test value"},
    )
    assert get_header(httpx_mock, auth).get("Authorization") == "Bearer waka_tok_12345"
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_multiple_scopes_are_comma_separated(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope=["email", "read_stats"],
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email%2Cread_stats&response_type=code&state=34f21f9ea8be7b1dfd3dd1673a9aea7c3a1737228b4f08bc11ebacb88449afaa658811f8022e9962927a0ec42805c0e3cc5e6b0d9185308216b298a686001a1f&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=34f21f9ea8be7b1dfd3dd1673a9aea7c3a1737228b4f08bc11ebacb88449afaa658811f8022e9962927a0ec42805c0e3cc5e6b0d9185308216b298a686001a1f",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        html="access_token=waka_tok_12345&token_type=bearer&expires_in=3600&refresh_token=waka_ref_12345&scope=email&example_parameter=example_value",
        match_content=b"grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email%2Cread_stats&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
    )
    assert get_header(httpx_mock, auth).get("Authorization") == "Bearer waka_tok_12345"
    tab.assert_success(
        "You are now authenticated on 34f21f9ea8be7b1dfd3dd1673a9aea7c3a1737228b4f08bc11ebacb88449afaa658811f8022e9962927a0ec42805c0e3cc5e6b0d9185308216b298a686001a1f. You may close this tab."
    )


def test_oauth2_authorization_code_flow_get_code_is_sent_in_authorization_header_by_default(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        html="access_token=waka_tok_12345&token_type=bearer&expires_in=3600&refresh_token=waka_ref_12345&scope=email&example_parameter=example_value",
        match_content=b"grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
    )
    assert get_header(httpx_mock, auth).get("Authorization") == "Bearer waka_tok_12345"
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_json_response_is_handled_even_if_unused(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        json={
            "access_token": "waka_tok_12345",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "waka_ref_12345",
            "scope": "email",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
    )
    assert get_header(httpx_mock, auth).get("Authorization") == "Bearer waka_tok_12345"
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_oauth2_authorization_code_flow_get_code_is_expired_after_30_seconds_by_default(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    token_cache._add_token(
        key="5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=httpx_auth.oauth2_tokens._to_expiry(expires_in=29),
    )
    # Meaning a new one will be requested
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        html="access_token=waka_tok_12345&token_type=bearer&expires_in=3600&refresh_token=waka_ref_12345&scope=email&example_parameter=example_value",
        match_content=b"grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
    )
    assert get_header(httpx_mock, auth).get("Authorization") == "Bearer waka_tok_12345"
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_oauth2_authorization_code_flow_get_code_custom_expiry(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
        early_expiry=28,
    )
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    token_cache._add_token(
        key="5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
        token="waka_tok_12345",
        expiry=httpx_auth.oauth2_tokens._to_expiry(expires_in=29),
    )
    assert get_header(httpx_mock, auth).get("Authorization") == "Bearer waka_tok_12345"


def test_empty_token_is_invalid(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        html="access_token=&token_type=bearer&expires_in=3600&refresh_token=waka_ref_12345&scope=email&example_parameter=example_value",
        match_content=b"grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
    )
    with pytest.raises(httpx_auth.GrantNotProvided) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "access_token not provided within {'access_token': '', 'token_type': 'bearer', 'expires_in': '3600', 'refresh_token': 'waka_ref_12345', 'scope': 'email', 'example_parameter': 'example_value'}."
    )
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_with_invalid_grant_request_no_json(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        text="failure",
        status_code=400,
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert str(exception_info.value) == "failure"
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_request_error(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        json={"error": "invalid_request"},
        status_code=400,
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_request: The request is missing a required parameter, includes an "
        "unsupported parameter value (other than grant type), repeats a parameter, "
        "includes multiple credentials, utilizes more than one mechanism for "
        "authenticating the client, or is otherwise malformed."
    )
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_request_error_and_error_description(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        json={"error": "invalid_request", "error_description": "desc of the error"},
        status_code=400,
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert str(exception_info.value) == "invalid_request: desc of the error"
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_request_error_and_error_description_and_uri(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        json={
            "error": "invalid_request",
            "error_description": "desc of the error",
            "error_uri": "https://test_url",
        },
        status_code=400,
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == f"invalid_request: desc of the error\nMore information can be found on https://test_url"
    )
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_request_error_and_error_description_and_uri_and_other_fields(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        json={
            "error": "invalid_request",
            "error_description": "desc of the error",
            "error_uri": "https://test_url",
            "other": "other info",
        },
        status_code=400,
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_request: desc of the error\nMore information can be found on https://test_url\nAdditional information: {'other': 'other info'}"
    )
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_with_invalid_grant_request_without_error(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        json={"other": "other info"},
        status_code=400,
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert str(exception_info.value) == "{'other': 'other info'}"
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_client_error(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        json={"error": "invalid_client"},
        status_code=400,
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
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
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_grant_error(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        json={"error": "invalid_grant"},
        status_code=400,
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_grant: The provided authorization grant (e.g., authorization code, "
        "resource owner credentials) or refresh token is invalid, expired, revoked, "
        "does not match the redirection URI used in the authorization request, or was "
        "issued to another client."
    )
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_with_invalid_grant_request_unauthorized_client_error(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        json={"error": "unauthorized_client"},
        status_code=400,
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "unauthorized_client: The authenticated client is not authorized to use this "
        "authorization grant type."
    )
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_with_invalid_grant_request_unsupported_grant_type_error(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        json={"error": "unsupported_grant_type"},
        status_code=400,
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "unsupported_grant_type: The authorization grant type is not supported by the "
        "authorization server."
    )
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_scope_error(
    token_cache, httpx_mock: HTTPXMock, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://wakatime.com/oauth/token",
        json={"error": "invalid_scope"},
        status_code=400,
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_scope: The requested scope is invalid, unknown, malformed, or "
        "exceeds the scope granted by the resource owner."
    )
    tab.assert_success(
        "You are now authenticated on 5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a. You may close this tab."
    )


def test_with_invalid_token_request_invalid_request_error(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_request",
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_request: The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."
    )
    tab.assert_failure(
        "Unable to properly perform authentication: invalid_request: The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."
    )


def test_with_invalid_token_request_invalid_request_error_and_error_description(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_request&error_description=desc",
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert str(exception_info.value) == "invalid_request: desc"
    tab.assert_failure(
        "Unable to properly perform authentication: invalid_request: desc"
    )


def test_with_invalid_token_request_invalid_request_error_and_error_description_and_uri(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_request&error_description=desc&error_uri=https://test_url",
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_request: desc\nMore information can be found on https://test_url"
    )
    tab.assert_failure(
        "Unable to properly perform authentication: invalid_request: desc\nMore information can be found on https://test_url"
    )


def test_with_invalid_token_request_invalid_request_error_and_error_description_and_uri_and_other_fields(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_request&error_description=desc&error_uri=https://test_url&other=test",
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_request: desc\nMore information can be found on https://test_url\nAdditional information: {'other': ['test']}"
    )
    tab.assert_failure(
        "Unable to properly perform authentication: invalid_request: desc\nMore information can be found on https://test_url\nAdditional information: {'other': ['test']}"
    )


def test_with_invalid_token_request_unauthorized_client_error(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=unauthorized_client",
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "unauthorized_client: The client is not authorized to request an authorization code or an access token using this method."
    )
    tab.assert_failure(
        "Unable to properly perform authentication: unauthorized_client: The client is not authorized to request an authorization code or an access token using this method."
    )


def test_with_invalid_token_request_access_denied_error(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=access_denied",
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "access_denied: The resource owner or authorization server denied the request."
    )
    tab.assert_failure(
        "Unable to properly perform authentication: access_denied: The resource owner or authorization server denied the request."
    )


def test_with_invalid_token_request_unsupported_response_type_error(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=unsupported_response_type",
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "unsupported_response_type: The authorization server does not support obtaining an authorization code or an access token using this method."
    )
    tab.assert_failure(
        "Unable to properly perform authentication: unsupported_response_type: The authorization server does not support obtaining an authorization code or an access token using this method."
    )


def test_with_invalid_token_request_invalid_scope_error(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=invalid_scope",
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "invalid_scope: The requested scope is invalid, unknown, or malformed."
    )
    tab.assert_failure(
        "Unable to properly perform authentication: invalid_scope: The requested scope is invalid, unknown, or malformed."
    )


def test_with_invalid_token_request_server_error_error(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=server_error",
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "server_error: The authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )
    tab.assert_failure(
        "Unable to properly perform authentication: server_error: The authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )


def test_with_invalid_token_request_temporarily_unavailable_error(
    token_cache, browser_mock: BrowserMock
):
    auth = httpx_auth.WakaTimeAuthorizationCode(
        "jPJQV0op6Pu3b66MWDi8b1wD",
        "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
        scope="email",
    )
    tab = browser_mock.add_response(
        opened_url="https://wakatime.com/oauth/authorize?client_id=jPJQV0op6Pu3b66MWDi8b1wD&client_secret=waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU&scope=email&response_type=code&state=5d0adb208bdbecaf5cfb6de0bf4ba0aea52986f3fc5ea7bc30c4b2db449c17e5c9d15f9a3926476cdaf1c72e9f73c7cfdc624dde0187c38d8c6b04532770df2a&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F",
        reply_url="http://localhost:5000#error=temporarily_unavailable",
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert (
        str(exception_info.value)
        == "temporarily_unavailable: The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.  (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )
    tab.assert_failure(
        "Unable to properly perform authentication: temporarily_unavailable: The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.  (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)"
    )


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.WakaTimeAuthorizationCode(
            "jPJQV0op6Pu3b66MWDi8b1wD",
            "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
            scope="email",
            header_value="Bearer token",
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."


def test_empty_scope_is_invalid():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.WakaTimeAuthorizationCode(
            "jPJQV0op6Pu3b66MWDi8b1wD",
            "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
            scope="",
        )
    assert str(exception_info.value) == "Scope is mandatory."


def test_scope_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.WakaTimeAuthorizationCode(
            "jPJQV0op6Pu3b66MWDi8b1wD",
            "waka_sec_0c4MBGeR9LN74LzV5uelF9SgeQ32CqfeWpIuieneBbsL57dAAlqqJWDiVDJOlsSx61pVwHMKlsb3uMvU",
            scope=None,
        )
    assert str(exception_info.value) == "Scope is mandatory."
