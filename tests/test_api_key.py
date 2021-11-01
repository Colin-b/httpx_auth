import pytest
from pytest_httpx import HTTPXMock
import httpx


import httpx_auth
from tests.auth_helper import get_header


def test_header_api_key_requires_an_api_key():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.HeaderApiKey(None)
    assert str(exception_info.value) == "API Key is mandatory."


def test_query_api_key_requires_an_api_key():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.QueryApiKey(None)
    assert str(exception_info.value) == "API Key is mandatory."


def test_header_api_key_is_sent_in_x_api_key_by_default(httpx_mock: HTTPXMock):
    auth = httpx_auth.HeaderApiKey("my_provided_api_key")
    assert get_header(httpx_mock, auth).get("X-Api-Key") == "my_provided_api_key"


def test_query_api_key_is_sent_in_api_key_by_default(httpx_mock: HTTPXMock):
    auth = httpx_auth.QueryApiKey("my_provided_api_key")
    # Mock a dummy response
    httpx_mock.add_response(url="https://authorized_only?api_key=my_provided_api_key")
    # Send a request to this dummy URL with authentication
    httpx.get("https://authorized_only", auth=auth)


def test_header_api_key_can_be_sent_in_a_custom_field_name(httpx_mock: HTTPXMock):
    auth = httpx_auth.HeaderApiKey("my_provided_api_key", "X-API-HEADER-KEY")
    assert get_header(httpx_mock, auth).get("X-Api-Header-Key") == "my_provided_api_key"


def test_query_api_key_can_be_sent_in_a_custom_field_name(httpx_mock: HTTPXMock):
    auth = httpx_auth.QueryApiKey("my_provided_api_key", "X-API-QUERY-KEY")
    # Mock a dummy response
    httpx_mock.add_response(
        url="https://authorized_only?X-API-QUERY-KEY=my_provided_api_key"
    )
    # Send a request to this dummy URL with authentication
    httpx.get("https://authorized_only", auth=auth)
