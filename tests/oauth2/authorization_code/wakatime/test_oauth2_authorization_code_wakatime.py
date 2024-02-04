import pytest

import httpx_auth


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
