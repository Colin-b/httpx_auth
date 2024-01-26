import time

from pytest_httpx import HTTPXMock
import pytest
import httpx

import httpx_auth
from tests.auth_helper import get_header
from httpx_auth.testing import BrowserMock, browser_mock, token_cache


def test_oauth2_pkce_flow_uses_provided_client(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    client = httpx.Client(headers={"x-test": "Test value"})
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token", client=client
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"code_verifier=MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
        match_headers={"x-test": "Test value"},
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )
    tab.assert_success(
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_oauth2_pkce_flow_is_able_to_reuse_client(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    client = httpx.Client(headers={"x-test": "Test value"})
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token", client=client
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 10,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"code_verifier=MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
        match_headers={"x-test": "Test value"},
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )
    tab.assert_success(
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )
    time.sleep(10)
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )
    tab.assert_success(
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_oauth2_pkce_flow_get_code_is_sent_in_authorization_header_by_default(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"code_verifier=MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )
    tab.assert_success(
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_oauth2_pkce_flow_get_code_is_expired_after_30_seconds_by_default(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    token_cache._add_token(
        key="ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=httpx_auth.oauth2_tokens._to_expiry(expires_in=29),
    )
    # Meaning a new one will be requested
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"code_verifier=MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )
    tab.assert_success(
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_oauth2_pkce_flow_get_code_custom_expiry(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token", early_expiry=28
    )
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    token_cache._add_token(
        key="ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=httpx_auth.oauth2_tokens._to_expiry(expires_in=29),
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )


def test_expires_in_sent_as_str(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": "3600",
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"code_verifier=MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )
    tab.assert_success(
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_nonce_is_sent_if_provided_in_authorization_url(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code?nonce=123456", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%27123456%27%5D&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"code_verifier=MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&response_type=code&code=SplxlOBeZQQYbYS6WxSbIA",
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )
    tab.assert_success(
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_with_invalid_grant_request_no_json(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code?nonce=123456", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%27123456%27%5D&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        text="failure",
        status_code=400,
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert str(exception_info.value) == "failure"
    tab.assert_success(
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_request_error(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code?nonce=123456", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%27123456%27%5D&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
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
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_request_error_and_error_description(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code?nonce=123456", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%27123456%27%5D&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={"error": "invalid_request", "error_description": "desc of the error"},
        status_code=400,
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert str(exception_info.value) == "invalid_request: desc of the error"
    tab.assert_success(
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_request_error_and_error_description_and_uri(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code?nonce=123456", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%27123456%27%5D&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
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
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_request_error_and_error_description_and_uri_and_other_fields(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code?nonce=123456", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%27123456%27%5D&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
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
        == f"invalid_request: desc of the error\nMore information can be found on https://test_url\nAdditional information: {{'other': 'other info'}}"
    )
    tab.assert_success(
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_with_invalid_grant_request_without_error(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code?nonce=123456", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%27123456%27%5D&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={"other": "other info"},
        status_code=400,
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert str(exception_info.value) == "{'other': 'other info'}"
    tab.assert_success(
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_client_error(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code?nonce=123456", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%27123456%27%5D&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
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
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_grant_error(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code?nonce=123456", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%27123456%27%5D&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
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
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_with_invalid_grant_request_unauthorized_client_error(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code?nonce=123456", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%27123456%27%5D&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
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
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_with_invalid_grant_request_unsupported_grant_type_error(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code?nonce=123456", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%27123456%27%5D&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
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
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_with_invalid_grant_request_invalid_scope_error(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code?nonce=123456", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&nonce=%5B%27123456%27%5D&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
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
        "You are now authenticated on ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5. You may close this tab."
    )


def test_with_invalid_token_request_invalid_request_error(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
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
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#error=invalid_request&error_description=desc",
    )
    with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
        httpx.get("https://authorized_only", auth=auth)
    assert str(exception_info.value) == "invalid_request: desc"
    tab.assert_failure(
        "Unable to properly perform authentication: invalid_request: desc"
    )


def test_with_invalid_token_request_invalid_request_error_and_error_description_and_uri(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
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
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
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
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
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
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
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
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
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
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
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
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
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
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code", "https://provide_access_token"
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=code&state=ce9c755b41b5e3c5b64c70598715d5de271023a53f39a67a70215d265d11d2bfb6ef6e9c701701e998e69cbdbf2cee29fd51d2a950aa05f59a20cf4a646099d5&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
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


def test_response_type_can_be_provided_in_url(
    token_cache, httpx_mock: HTTPXMock, monkeypatch, browser_mock: BrowserMock
):
    monkeypatch.setattr(httpx_auth.authentication.os, "urandom", lambda x: b"1" * 63)
    auth = httpx_auth.OAuth2AuthorizationCodePKCE(
        "https://provide_code?response_type=my_code",
        "https://provide_access_token",
        response_type="not_used",
    )
    tab = browser_mock.add_response(
        opened_url="https://provide_code?response_type=%5B%27my_code%27%5D&state=863572fb4a5d1cc06834070baaaa08020928779095e2b61a60513e55a7ad17e9683441b436080a1c654a58b8f5c35837ee96e610919075ea01c82e27b6a86219&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&code_challenge=5C_ph_KZ3DstYUc965SiqmKAA-ShvKF4Ut7daKd3fjc&code_challenge_method=S256",
        reply_url="http://localhost:5000#code=SplxlOBeZQQYbYS6WxSbIA&state=863572fb4a5d1cc06834070baaaa08020928779095e2b61a60513e55a7ad17e9683441b436080a1c654a58b8f5c35837ee96e610919075ea01c82e27b6a86219",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"code_verifier=MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F&response_type=my_code&code=SplxlOBeZQQYbYS6WxSbIA",
    )
    assert (
        get_header(httpx_mock, auth).get("Authorization")
        == "Bearer 2YotnFZFEjr1zCsicMWpAA"
    )
    tab.assert_success(
        "You are now authenticated on 863572fb4a5d1cc06834070baaaa08020928779095e2b61a60513e55a7ad17e9683441b436080a1c654a58b8f5c35837ee96e610919075ea01c82e27b6a86219. You may close this tab."
    )


def test_authorization_url_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OAuth2AuthorizationCodePKCE("", "https://test_url")
    assert str(exception_info.value) == "Authorization URL is mandatory."


def test_token_url_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OAuth2AuthorizationCodePKCE("https://test_url", "")
    assert str(exception_info.value) == "Token URL is mandatory."


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OAuth2AuthorizationCodePKCE(
            "https://test_url", "https://test_url", header_value="Bearer token"
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
