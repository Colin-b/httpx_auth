import pytest

import httpx_auth


def test_header_value_must_contains_token():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.OktaAuthorizationCodePKCE(
            "test_url",
            "54239d18-c68c-4c47-8bdd-ce71ea1d50cd",
            header_value="Bearer token",
        )
    assert str(exception_info.value) == "header_value parameter must contains {token}."
