import time

from pytest_httpx import HTTPXMock
import pytest
import httpx

import httpx_auth
from httpx_auth.testing import token_cache
from httpx_auth._oauth2.tokens import to_expiry


def test_oauth2_client_credentials_flow_uses_provided_client(
    token_cache, httpx_mock: HTTPXMock
):
    client = httpx.Client(headers={"x-test": "Test value"})
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token",
        client_id="test_user",
        client_secret="test_pwd",
        client=client,
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_headers={"x-test": "Test value"},
        match_content=b"grant_type=client_credentials",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_oauth2_client_credentials_flow_is_able_to_reuse_client(
    token_cache, httpx_mock: HTTPXMock
):
    client = httpx.Client(headers={"x-test": "Test value"})
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token",
        client_id="test_user",
        client_secret="test_pwd",
        client=client,
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 2,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_headers={"x-test": "Test value"},
        match_content=b"grant_type=client_credentials",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)

    time.sleep(2)

    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 10,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_headers={"x-test": "Test value"},
        match_content=b"grant_type=client_credentials",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )
    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_oauth2_client_credentials_flow_token_is_sent_in_authorization_header_by_default(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=client_credentials",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_oauth2_client_credentials_flow_token_is_expired_after_30_seconds_by_default(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    token_cache._add_token(
        key="fcd9be12271843a292d3c87c6051ea3dd54ee66d4938d15ebda9c7492d51fe555064fa9f787d0fb207a76558ae33e57ac11cb7aee668d665db9c6c1d60c5c314",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=to_expiry(expires_in=29),
    )
    # Meaning a new one will be requested
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=client_credentials",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_oauth2_client_credentials_flow_token_custom_expiry(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token",
        client_id="test_user",
        client_secret="test_pwd",
        early_expiry=28,
    )
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    token_cache._add_token(
        key="fcd9be12271843a292d3c87c6051ea3dd54ee66d4938d15ebda9c7492d51fe555064fa9f787d0fb207a76558ae33e57ac11cb7aee668d665db9c6c1d60c5c314",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=to_expiry(expires_in=29),
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_expires_in_sent_as_str(token_cache, httpx_mock: HTTPXMock):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": "3600",
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=client_credentials",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_with_invalid_grant_request_no_json(token_cache, httpx_mock: HTTPXMock):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        text="failure",
        status_code=400,
        match_content=b"grant_type=client_credentials",
    )
    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest, match="failure"):
            client.get("https://authorized_only", auth=auth)


def test_with_invalid_grant_request_invalid_request_error(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={"error": "invalid_request"},
        status_code=400,
        match_content=b"grant_type=client_credentials",
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "invalid_request: The request is missing a required parameter, includes an "
        "unsupported parameter value (other than grant type), repeats a parameter, "
        "includes multiple credentials, utilizes more than one mechanism for "
        "authenticating the client, or is otherwise malformed."
    )


def test_with_invalid_grant_request_invalid_request_error_and_error_description(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={"error": "invalid_request", "error_description": "desc of the error"},
        status_code=400,
        match_content=b"grant_type=client_credentials",
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert str(exception_info.value) == "invalid_request: desc of the error"


def test_with_invalid_grant_request_invalid_request_error_and_error_description_and_uri(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "error": "invalid_request",
            "error_description": "desc of the error",
            "error_uri": "https://test_url",
        },
        status_code=400,
        match_content=b"grant_type=client_credentials",
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == f"invalid_request: desc of the error\nMore information can be found on https://test_url"
    )


def test_with_invalid_grant_request_invalid_request_error_and_error_description_and_uri_and_other_fields(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "error": "invalid_request",
            "error_description": "desc of the error",
            "error_uri": "https://test_url",
            "other": "other info",
        },
        status_code=400,
        match_content=b"grant_type=client_credentials",
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == f"invalid_request: desc of the error\nMore information can be found on https://test_url\nAdditional information: {{'other': 'other info'}}"
    )


def test_with_invalid_grant_request_without_error(token_cache, httpx_mock: HTTPXMock):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={"other": "other info"},
        status_code=400,
        match_content=b"grant_type=client_credentials",
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert str(exception_info.value) == "{'other': 'other info'}"


def test_with_invalid_grant_request_invalid_client_error(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={"error": "invalid_client"},
        status_code=400,
        match_content=b"grant_type=client_credentials",
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "invalid_client: Client authentication failed (e.g., unknown client, no "
        "client authentication included, or unsupported authentication method).  The "
        "authorization server MAY return an HTTP 401 (Unauthorized) status code to "
        "indicate which HTTP authentication schemes are supported.  If the client "
        'attempted to authenticate via the "Authorization" request header field, the '
        "authorization server MUST respond with an HTTP 401 (Unauthorized) status "
        'code and include the "WWW-Authenticate" response header field matching the '
        "authentication scheme used by the client."
    )


def test_with_invalid_grant_request_invalid_grant_error(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={"error": "invalid_grant"},
        status_code=400,
        match_content=b"grant_type=client_credentials",
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "invalid_grant: The provided authorization grant (e.g., authorization code, "
        "resource owner credentials) or refresh token is invalid, expired, revoked, "
        "does not match the redirection URI used in the authorization request, or was "
        "issued to another client."
    )


def test_with_invalid_grant_request_unauthorized_client_error(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={"error": "unauthorized_client"},
        status_code=400,
        match_content=b"grant_type=client_credentials",
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "unauthorized_client: The authenticated client is not authorized to use this "
        "authorization grant type."
    )


def test_with_invalid_grant_request_unsupported_grant_type_error(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={"error": "unsupported_grant_type"},
        status_code=400,
        match_content=b"grant_type=client_credentials",
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "unsupported_grant_type: The authorization grant type is not supported by the "
        "authorization server."
    )


def test_with_invalid_grant_request_invalid_scope_error(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token", client_id="test_user", client_secret="test_pwd"
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={"error": "invalid_scope"},
        status_code=400,
        match_content=b"grant_type=client_credentials",
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "invalid_scope: The requested scope is invalid, unknown, malformed, or "
        "exceeds the scope granted by the resource owner."
    )


@pytest.mark.parametrize(
    "client_id1, client_secret1, client_id2, client_secret2",
    [
        # Use the same client secret but for different client ids (different application)
        ("user1", "test_pwd", "user2", "test_pwd"),
        # Use the same client id but with different client secrets (update of secret)
        ("test_user", "old_pwd", "test_user", "new_pwd"),
    ],
)
def test_oauth2_client_credentials_flow_handle_credentials_as_part_of_cache_key(
    token_cache,
    httpx_mock: HTTPXMock,
    client_id1,
    client_secret1,
    client_id2,
    client_secret2,
):
    auth1 = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token",
        client_id=client_id1,
        client_secret=client_secret1,
    )
    auth2 = httpx_auth.OAuth2ClientCredentials(
        "https://provide_access_token",
        client_id=client_id2,
        client_secret=client_secret2,
    )
    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=client_credentials",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth1)

    httpx_mock.add_response(
        method="POST",
        url="https://provide_access_token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAB",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIB",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=client_credentials",
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAB",
        },
    )

    # This should request a new token (different credentials)
    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth2)

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAB",
        },
    )
    # Ensure the proper token is fetched
    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth1)
        client.get("https://authorized_only", auth=auth2)
