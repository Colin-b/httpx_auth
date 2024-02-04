import pytest

import httpx_auth


def test_header_api_key_requires_an_api_key():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.HeaderApiKey(None)
    assert str(exception_info.value) == "API Key is mandatory."


def test_query_api_key_requires_an_api_key():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.QueryApiKey(None)
    assert str(exception_info.value) == "API Key is mandatory."
