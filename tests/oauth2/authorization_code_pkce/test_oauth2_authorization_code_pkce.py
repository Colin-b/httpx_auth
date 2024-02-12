import pytest

import httpx_auth


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
