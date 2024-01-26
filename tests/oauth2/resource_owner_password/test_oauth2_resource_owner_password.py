import pytest

import httpx_auth


def test_token_url_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OAuth2ResourceOwnerPasswordCredentials("", "test_user", "test_pwd")
    assert str(exception_info.value) == "Token URL is mandatory."


def test_user_name_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OAuth2ResourceOwnerPasswordCredentials(
            "https://test_url", "", "test_pwd"
        )
    assert str(exception_info.value) == "User name is mandatory."


def test_password_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OAuth2ResourceOwnerPasswordCredentials(
            "https://test_url", "test_user", ""
        )
    assert str(exception_info.value) == "Password is mandatory."


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OAuth2ResourceOwnerPasswordCredentials(
            "https://test_url", "test_user", "test_pwd", header_value="Bearer token"
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
