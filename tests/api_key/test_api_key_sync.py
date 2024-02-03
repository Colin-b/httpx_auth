from pytest_httpx import HTTPXMock
import httpx


import httpx_auth


def test_header_api_key_is_sent_in_x_api_key_by_default(httpx_mock: HTTPXMock):
    auth = httpx_auth.HeaderApiKey("my_provided_api_key")

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={"X-API-Key": "my_provided_api_key"},
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_query_api_key_is_sent_in_api_key_by_default(httpx_mock: HTTPXMock):
    auth = httpx_auth.QueryApiKey("my_provided_api_key")

    httpx_mock.add_response(
        url="https://authorized_only?api_key=my_provided_api_key", method="GET"
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_header_api_key_can_be_sent_in_a_custom_field_name(httpx_mock: HTTPXMock):
    auth = httpx_auth.HeaderApiKey("my_provided_api_key", "X-API-HEADER-KEY")

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={"X-API-HEADER-KEY": "my_provided_api_key"},
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_query_api_key_can_be_sent_in_a_custom_field_name(httpx_mock: HTTPXMock):
    auth = httpx_auth.QueryApiKey("my_provided_api_key", "X-API-QUERY-KEY")

    httpx_mock.add_response(
        url="https://authorized_only?X-API-QUERY-KEY=my_provided_api_key", method="GET"
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)
