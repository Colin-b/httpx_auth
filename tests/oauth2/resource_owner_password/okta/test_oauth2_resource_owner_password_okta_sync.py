import time

from pytest_httpx import HTTPXMock
import pytest
import httpx

import httpx_auth
from httpx_auth.testing import token_cache
from httpx_auth._oauth2.tokens import to_expiry


def test_oauth2_password_credentials_flow_uses_provided_client(
    token_cache, httpx_mock: HTTPXMock
):
    client = httpx.Client(headers={"x-test": "Test value"})
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
        client=client,
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=password&username=test_user&password=test_pwd&scope=openid",
        match_headers={
            "x-test": "Test value",
            "Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI=",
        },
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


def test_oauth2_password_credentials_flow_is_able_to_reuse_client(
    token_cache, httpx_mock: HTTPXMock
):
    client = httpx.Client(headers={"x-test": "Test value"})
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
        client=client,
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 2,
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=password&username=test_user&password=test_pwd&scope=openid",
        match_headers={
            "x-test": "Test value",
            "Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI=",
        },
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
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 10,
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=password&username=test_user&password=test_pwd&scope=openid",
        match_headers={
            "x-test": "Test value",
            "Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI=",
        },
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


def test_oauth2_password_credentials_flow_is_able_to_reuse_client_with_token_refresh(
    token_cache, httpx_mock: HTTPXMock
):
    client = httpx.Client(headers={"x-test": "Test value"})
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
        client=client,
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 2,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=password&username=test_user&password=test_pwd&scope=openid",
        match_headers={
            "x-test": "Test value",
            "Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI=",
        },
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
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "rVR7Syg5bjZtZYjbZIW",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=refresh_token&scope=openid&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA",
        match_headers={
            "x-test": "Test value",
            "Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI=",
        },
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer rVR7Syg5bjZtZYjbZIW",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_oauth2_password_credentials_flow_token_is_sent_in_authorization_header_by_default(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=password&username=test_user&password=test_pwd&scope=openid",
        match_headers={"Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI="},
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


def test_oauth2_password_credentials_flow_token_is_expired_after_30_seconds_by_default(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    # Add a token that expires in 29 seconds, so should be considered as expired when issuing the request
    token_cache._add_token(
        key="bdc39831ac59c0f65d36761e9b65656ae76223f2284c393a6e93fe4e09a2c0002e2638bbe02db2cc62928a2357be5e2e93b9fa4ac68729f4d28da180caae912a",
        token="2YotnFZFEjr1zCsicMWpAA",
        expiry=to_expiry(expires_in=29),
    )
    # Meaning a new one will be requested
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=password&username=test_user&password=test_pwd&scope=openid",
        match_headers={"Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI="},
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


def test_oauth2_password_credentials_flow_token_custom_expiry(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
        early_expiry=28,
    )
    # Add a token that expires in 29 seconds, so should be considered as not expired when issuing the request
    token_cache._add_token(
        key="bdc39831ac59c0f65d36761e9b65656ae76223f2284c393a6e93fe4e09a2c0002e2638bbe02db2cc62928a2357be5e2e93b9fa4ac68729f4d28da180caae912a",
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


def test_oauth2_password_credentials_flow_refresh_token(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": "0",
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=password&username=test_user&password=test_pwd&scope=openid",
        match_headers={
            "Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI=",
        },
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

    # response for refresh token grant
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "rVR7Syg5bjZtZYjbZIW",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=refresh_token&scope=openid&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA",
        match_headers={
            "Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI=",
        },
    )
    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer rVR7Syg5bjZtZYjbZIW",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_oauth2_password_credentials_flow_refresh_token_invalid(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": "0",
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=password&username=test_user&password=test_pwd&scope=openid",
        match_headers={
            "Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI=",
        },
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

    # response for refresh token grant
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_request"},
        status_code=400,
        match_content=b"grant_type=refresh_token&scope=openid&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA",
        match_headers={
            "Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI=",
        },
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": "0",
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=password&username=test_user&password=test_pwd&scope=openid",
        match_headers={
            "Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI=",
        },
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


def test_oauth2_password_credentials_flow_refresh_token_access_token_not_expired(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=password&username=test_user&password=test_pwd&scope=openid",
        match_headers={
            "Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI=",
        },
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

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "Authorization": "Bearer 2YotnFZFEjr1zCsicMWpAA",
        },
    )
    # expect Bearer token to remain the same
    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)


def test_expires_in_sent_as_str(token_cache, httpx_mock: HTTPXMock):
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": "3600",
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=password&username=test_user&password=test_pwd&scope=openid",
        match_headers={"Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI="},
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


def test_scope_is_sent_as_is_when_provided_as_str(token_cache, httpx_mock: HTTPXMock):
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
        scope="my_scope+my_other_scope",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=password&username=test_user&password=test_pwd&scope=my_scope%2Bmy_other_scope",
        match_headers={"Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI="},
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


def test_scope_is_sent_as_str_when_provided_as_list(token_cache, httpx_mock: HTTPXMock):
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
        scope=["my_scope", "my_other_scope"],
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
        match_content=b"grant_type=password&username=test_user&password=test_pwd&scope=my_scope+my_other_scope",
        match_headers={"Authorization": "Basic dGVzdF91c2VyMjp0ZXN0X3B3ZDI="},
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
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        text="failure",
        status_code=400,
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest, match="failure"):
            client.get("https://authorized_only", auth=auth)


def test_with_invalid_grant_request_invalid_request_error(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_request"},
        status_code=400,
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
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_request", "error_description": "desc of the error"},
        status_code=400,
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert str(exception_info.value) == "invalid_request: desc of the error"


def test_with_invalid_grant_request_invalid_request_error_and_error_description_and_uri(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "error": "invalid_request",
            "error_description": "desc of the error",
            "error_uri": "https://test_url",
        },
        status_code=400,
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
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "error": "invalid_request",
            "error_description": "desc of the error",
            "error_uri": "https://test_url",
            "other": "other info",
        },
        status_code=400,
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == f"invalid_request: desc of the error\nMore information can be found on https://test_url\nAdditional information: {{'other': 'other info'}}"
    )


def test_with_invalid_grant_request_without_error(token_cache, httpx_mock: HTTPXMock):
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"other": "other info"},
        status_code=400,
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert str(exception_info.value) == "{'other': 'other info'}"


def test_with_invalid_grant_request_invalid_client_error(
    token_cache, httpx_mock: HTTPXMock
):
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_client"},
        status_code=400,
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
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_grant"},
        status_code=400,
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
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "unauthorized_client"},
        status_code=400,
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
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "unsupported_grant_type"},
        status_code=400,
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
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={"error": "invalid_scope"},
        status_code=400,
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.InvalidGrantRequest) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "invalid_scope: The requested scope is invalid, unknown, malformed, or "
        "exceeds the scope granted by the resource owner."
    )


def test_without_expected_token(token_cache, httpx_mock: HTTPXMock):
    auth = httpx_auth.OktaResourceOwnerPasswordCredentials(
        "testserver.okta-emea.com",
        username="test_user",
        password="test_pwd",
        client_id="test_user2",
        client_secret="test_pwd2",
        token_field_name="not_provided",
    )
    httpx_mock.add_response(
        method="POST",
        url="https://testserver.okta-emea.com/oauth2/default/v1/token",
        json={
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value",
        },
    )

    with httpx.Client() as client:
        with pytest.raises(httpx_auth.GrantNotProvided) as exception_info:
            client.get("https://authorized_only", auth=auth)

    assert (
        str(exception_info.value)
        == "not_provided not provided within {'access_token': '2YotnFZFEjr1zCsicMWpAA', 'token_type': 'example', 'expires_in': 3600, 'refresh_token': 'tGzv3JOkF0XG5Qx2TlKWIA', 'example_parameter': 'example_value'}."
    )
