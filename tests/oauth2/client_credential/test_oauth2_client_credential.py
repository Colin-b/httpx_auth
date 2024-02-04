import pytest

import httpx_auth


def test_token_url_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OAuth2ClientCredentials("", "test_user", "test_pwd")
    assert str(exception_info.value) == "Token URL is mandatory."


def test_client_id_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OAuth2ClientCredentials("https://test_url", "", "test_pwd")
    assert str(exception_info.value) == "client_id is mandatory."


def test_client_secret_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OAuth2ClientCredentials("https://test_url", "test_user", "")
    assert str(exception_info.value) == "client_secret is mandatory."


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OAuth2ClientCredentials(
            "https://test_url", "test_user", "test_pwd", header_value="Bearer token"
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
