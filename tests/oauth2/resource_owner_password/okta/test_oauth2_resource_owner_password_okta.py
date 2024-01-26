import pytest

import httpx_auth


def test_instance_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OktaResourceOwnerPasswordCredentials(
            "",
            "test_user",
            "test_pwd",
            client_id="test_user2",
            client_secret="test_pwd2",
        )
    assert str(exception_info.value) == "Instance is mandatory."


def test_user_name_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OktaResourceOwnerPasswordCredentials(
            "https://test_url",
            "",
            "test_pwd",
            client_id="test_user2",
            client_secret="test_pwd2",
        )
    assert str(exception_info.value) == "User name is mandatory."


def test_password_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OktaResourceOwnerPasswordCredentials(
            "https://test_url",
            "test_user",
            "",
            client_id="test_user2",
            client_secret="test_pwd2",
        )
    assert str(exception_info.value) == "Password is mandatory."


def test_client_id_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OktaResourceOwnerPasswordCredentials(
            "https://test_url",
            "test_user",
            "test_pwd",
            client_id="",
            client_secret="test_pwd2",
        )
    assert str(exception_info.value) == "Client ID is mandatory."


def test_client_secret_is_mandatory():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OktaResourceOwnerPasswordCredentials(
            "https://test_url",
            "test_user",
            "test_pwd",
            client_id="test_user2",
            client_secret="",
        )
    assert str(exception_info.value) == "Client secret is mandatory."


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OktaResourceOwnerPasswordCredentials(
            "https://test_url",
            "test_user",
            "test_pwd",
            client_id="test_user2",
            client_secret="test_pwd2",
            header_value="Bearer token",
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
