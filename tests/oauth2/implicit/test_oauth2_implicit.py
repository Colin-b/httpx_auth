import pytest

import httpx_auth


def test_oauth2_implicit_flow_url_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OAuth2Implicit(None)
    assert str(exception_info.value) == "Authorization URL is mandatory."


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OAuth2Implicit("https://test_url", header_value="Bearer token")
    assert str(exception_info.value) == "header_value parameter must contains {token}."
