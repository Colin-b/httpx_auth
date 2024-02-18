import pytest

import httpx_auth


def test_scope_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OktaClientCredentials("test_url", "test_user", "test_pwd", scope="")
    assert str(exception_info.value) == "scope is mandatory."


def test_instance_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OktaClientCredentials("", "test_user", "test_pwd", scope="dummy")
    assert str(exception_info.value) == "Okta instance is mandatory."


def test_client_id_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OktaClientCredentials("test_url", "", "test_pwd", scope="dummy")
    assert str(exception_info.value) == "client_id is mandatory."


def test_client_secret_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OktaClientCredentials("test_url", "test_user", "", scope="dummy")
    assert str(exception_info.value) == "client_secret is mandatory."


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OktaClientCredentials(
            "test_url",
            "test_user",
            "test_pwd",
            scope="dummy",
            header_value="Bearer token",
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
