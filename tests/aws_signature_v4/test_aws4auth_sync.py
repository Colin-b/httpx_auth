from urllib.parse import quote

import pytest
import time_machine
from pytest_httpx import HTTPXMock
import httpx

import httpx_auth


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_without_content_in_request(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=ce708380ee69b1a9558b9b0dddd4d15f35a2a5e5ea3534b541247f1a746626db",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.post("https://authorized_only", auth=auth)


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_with_content_in_request(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="POST",
        match_json=[{"key": "value"}],
        match_headers={
            "x-amz-content-sha256": "fb65c1441d6743274738fe3b3042a73167ba1fb2d34679d8dd16433473758f97",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=5f4f832a19fc834d4f34047289ad67d96da25bd414a70f02ce6b85aef9ab8068",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.post("https://authorized_only", json=[{"key": "value"}], auth=auth)


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_with_security_token_and_without_content_in_request(
    httpx_mock: HTTPXMock,
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        security_token="security_token",
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=2ae27ce5e8dcc005736c97ff857e4f44401fc3a33d8358b1d67c079f0f5a8b3e",
            "x-amz-date": "20181011T150505Z",
            "x-amz-security-token": "security_token",
        },
    )

    with httpx.Client() as client:
        client.post("https://authorized_only", auth=auth)


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_share_security_tokens_between_instances(
    httpx_mock: HTTPXMock,
):
    httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        security_token="security_token1",
    )
    auth2 = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        security_token="security_token",
    )
    assert auth2.include_headers == {
        "host",
        "content-type",
        "date",
        "x-amz-*",
        "x-amz-security-token",
    }

    httpx_mock.add_response(
        url="https://authorized_only",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=2ae27ce5e8dcc005736c97ff857e4f44401fc3a33d8358b1d67c079f0f5a8b3e",
            "x-amz-date": "20181011T150505Z",
            "x-amz-security-token": "security_token",
        },
    )

    with httpx.Client() as client:
        client.post("https://authorized_only", auth=auth2)


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_includes_custom_x_amz_headers(
    httpx_mock: HTTPXMock,
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        security_token="security_token",
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-custom;x-amz-date;x-amz-security-token, Signature=533d5180d16f23a2807de5675043e60a439f0a4e929fad4fa09395c0fb3276a4",
            "x-amz-date": "20181011T150505Z",
            "x-amz-security-token": "security_token",
            "X-AmZ-CustoM": "Custom",
        },
    )

    with httpx.Client() as client:
        client.post(
            "https://authorized_only", headers={"X-AmZ-CustoM": "Custom"}, auth=auth
        )


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_excludes_x_amz_client_context_header(
    httpx_mock: HTTPXMock,
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=ce708380ee69b1a9558b9b0dddd4d15f35a2a5e5ea3534b541247f1a746626db",
            "x-amz-date": "20181011T150505Z",
            "x-amz-Client-Context": "Custom",
        },
    )

    with httpx.Client() as client:
        client.post(
            "https://authorized_only",
            headers={"x-amz-Client-Context": "Custom"},
            auth=auth,
        )


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_allows_to_include_custom_and_default_forbidden_header(
    httpx_mock: HTTPXMock,
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        include_headers=[
            "Host",
            "content-type",
            "date",
            "cusTom",
            "x-aMz-client-context",
            "x-amz-*",
        ],
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=custom;host;x-amz-client-context;x-amz-content-sha256;x-amz-date, Signature=215c8030c2f238163ddfb291abcd9e5a02112a0db1363aa7cdb27ba1f646d987",
            "x-amz-date": "20181011T150505Z",
            "Custom": "Custom",
            "x-amz-Client-Context": "Context",
        },
    )

    with httpx.Client() as client:
        client.post(
            "https://authorized_only",
            headers={"Custom": "Custom", "x-amz-Client-Context": "Context"},
            auth=auth,
        )


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_does_not_strips_header_names(
    httpx_mock: HTTPXMock,
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        include_headers=[
            "Host",
            "content-type",
            "date",
            " cusTom ",
            "x-amz-*",
        ],
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders= custom ;host;x-amz-content-sha256;x-amz-date, Signature=6156fed4e0764085005828ab8017081e2f8e6d12167c860fe2a9ea2034915987",
            "x-amz-date": "20181011T150505Z",
            " Custom ": "Custom",
        },
    )

    with httpx.Client() as client:
        client.post(
            "https://authorized_only",
            headers={" Custom ": "Custom"},
            auth=auth,
        )


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_header_with_multiple_values(
    httpx_mock: HTTPXMock,
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        include_headers=[
            "Host",
            "content-type",
            "date",
            "cusTom",
            "x-amz-*",
        ],
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=custom;host;x-amz-content-sha256;x-amz-date, Signature=77fcee19291cb9334678ca7221729baab12848ce49225561477ce95c44222dfb",
            "x-amz-date": "20181011T150505Z",
            "Custom": "value2, value1",
            "custoM": "value3",
        },
    )

    with httpx.Client() as client:
        client.post(
            "https://authorized_only",
            headers=httpx.Headers(
                [("Custom", "value2"), ("Custom", "value1"), ("custoM", "value3")]
            ),
            auth=auth,
        )


@pytest.mark.parametrize(
    "decoded_value, signature",
    [
        [" a", "92c77bd0e66ae6f12fa41491ebcb524127b2df9677fd7ccf9ffff698021e0b28"],
        [
            ' "a   b   c"',
            "38fbdeb88fa3785191adc95113bcf665b4151cc2d2379e6a086bee9066f65a38",
        ],
        [
            '"a   b   c"',
            "38fbdeb88fa3785191adc95113bcf665b4151cc2d2379e6a086bee9066f65a38",
        ],
        [
            "a   b   c",
            "7b6aea4a2378417c631c5621ddc99a94591022c775cfbb9dbf5c360492e238ef",
        ],
        ["\nab", "3072938eb28cff19726cc2a27d5e570f916887a639b26475b390dd0edacf6496"],
    ],
)
@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_headers_encoded_values(
    httpx_mock: HTTPXMock, decoded_value: str, signature: str
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        include_headers=[
            "Host",
            "content-type",
            "date",
            "My-Header1",
            "x-amz-*",
        ],
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="POST",
        match_headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "x-amz-content-sha256": "a046bedaa571a3f49a4b24f7be550e21936278c76da670737dc2c9bcaa3be9a0",
            "Authorization": f"AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;my-header1;x-amz-content-sha256;x-amz-date, Signature={signature}",
            "x-amz-date": "20181011T150505Z",
            "My-Header1": decoded_value,
        },
    )

    with httpx.Client() as client:
        client.post(
            "https://authorized_only",
            headers={"My-Header1": decoded_value},
            auth=auth,
            data={"field": "value"},
        )


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_host_header_with_port(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        include_headers=[
            "Host",
            "content-type",
            "date",
            "x-amz-*",
        ],
    )

    httpx_mock.add_response(
        url="https://authorized_only:8443",
        method="GET",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": f"AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=6c4d64151fab428de4853175fe4dcef1a0c5e247741cc1095553627cc0234857",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.get(
            "https://authorized_only:8443",
            auth=auth,
        )


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_with_security_token_and_content_in_request(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        security_token="security_token",
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="POST",
        match_json=[{"key": "value"}],
        match_headers={
            "x-amz-content-sha256": "fb65c1441d6743274738fe3b3042a73167ba1fb2d34679d8dd16433473758f97",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=e02c4733589cf6e80361f6905564da6d0c23a0829bb3c3899b328e43b2f7b581",
            "x-amz-date": "20181011T150505Z",
            "x-amz-security-token": "security_token",
        },
    )

    with httpx.Client() as client:
        client.post("https://authorized_only", json=[{"key": "value"}], auth=auth)


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_override_x_amz_date_header(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=ce708380ee69b1a9558b9b0dddd4d15f35a2a5e5ea3534b541247f1a746626db",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.post(
            "https://authorized_only",
            headers={"x-amz-date": "20201011T150505Z"},
            auth=auth,
        )


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_root_path(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url="https://authorized_only/",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=ce708380ee69b1a9558b9b0dddd4d15f35a2a5e5ea3534b541247f1a746626db",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.post("https://authorized_only/", auth=auth)


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_query_parameters(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url="https://authorized_only?id-type=third&id=second*&id=first&id_type=fourth",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=dae483807ca8ff8365ac53cfaed8bdaf13984c66c0077567aba5533254ac8ae6",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.post(
            "https://authorized_only?id-type=third&id=second*&id=first&id_type=fourth",
            auth=auth,
        )


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_query_parameters_with_multiple_values(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url="https://authorized_only?foo=1&bar=2&bar=3&bar=1",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=02ca672d31c4eb22997eecdd064e3f99665018068676fdc1c91422023047ae02",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.post("https://authorized_only?foo=1&bar=2&bar=3&bar=1", auth=auth)


@pytest.mark.parametrize(
    "decoded_value, signature",
    [
        ["a&b", "cdf339d384d03577c7bd080971a9ba83038ba99c90d55886cccef4428a2c0633"],
        ["a=b", "e4e0fb580cb9b304f6fb5f7e9294156fb1b17f0d23a79e6ccfa86ec8120a5c7e"],
        ["a+b", "6eef487def6c062806b89437027e12f641f35e1dfda5cc7ae49da777ad5f0fb4"],
        ["a b", "581b79b3531e6cc21acc0bbd41422bae25de78c601eae88bd5287f96ec62f00e"],
        [
            "/?a=b&c=d",
            "4f1de21047c249b81a4065a3cb4b17d97047d8f86c6a830e0bee32fb2a714d9e",
        ],
    ],
)
@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_query_parameters_encoded_values(
    httpx_mock: HTTPXMock, decoded_value: str, signature: str
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url=f"https://authorized_only?foo={quote(decoded_value)}&bar=1",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": f"AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.post(
            "https://authorized_only",
            params={"foo": decoded_value, "bar": 1},
            auth=auth,
        )


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_query_reserved(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url=f"https://authorized_only/?@#$%25%5E&+=/,?%3E%3C%60%22;:%5C%7C][%7B%7D%20=@#$%25%5E&+=/,?%3E%3C%60%22;:%5C%7C][%7B%7D",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": f"AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=29d511750e5da2b049d42f55eee199f85ba375ab7412b801f806e1555a313d6e",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.post(
            r'https://authorized_only/?@#$%^&+=/,?><`";:\|][{} =@#$%^&+=/,?><`";:\|][{}',
            auth=auth,
        )


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_query_parameters_with_semicolon(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url=f"https://authorized_only?foo=value;bar=1",
        method="GET",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": f"AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=d8d77276658fbe9b7715811c0d55d34b545789cacfb8735fad8946d20ff74f37",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.get(
            "https://authorized_only?foo=value;bar=1",
            auth=auth,
        )


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_path_normalize(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url="https://authorized_only/stuff//more/",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=e49fb885d30c9e74901071748b783fabe8ba7a979aa20420ac76af1dda1edd03",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.post("https://authorized_only/./test/../stuff//more/", auth=auth)


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_path_quoting(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url="https://authorized_only/test/hello-*.&%5E~+%7B%7D!$%C2%A3_%20",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=f3c8efd9b81b952035a73ea93d3a79380e13370bcaa6089e4275319bde17a400",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.post("https://authorized_only/test/hello-*.&^~+{}!$£_ ", auth=auth)


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_path_percent_encode_non_s3(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url="https://authorized_only/test/%2a%2b%25/~-_%5E&%20%25%25",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=7b3267f1b4bcb1f6731eb99aa9b3381225c18fc32e3ecb78fc4adceb746f92f3",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.post("https://authorized_only/test/%2a%2b%25/~-_^& %%", auth=auth)


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_path_percent_encode_s3(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="s3",
    )

    httpx_mock.add_response(
        url="https://authorized_only/test/%2a%2b%25/~-_%5E&%20%25%25",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=dd3e44f87a05d1488fa5aca66702e8c53a0d0fa570564bc70941bc5c6d25016d",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.post("https://authorized_only/test/%2a%2b%25/~-_^& %%", auth=auth)


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_without_path(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=e3411118ac098a820690144b8b273aa64a3366d899fa68fd64a1ab950c982b4b",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.get("https://authorized_only", auth=auth)
