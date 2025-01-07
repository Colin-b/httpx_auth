import time

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
            "x-amz-content-sha256": "1e1d3e3fb0bcfb7b2b61f687369d0227e6aefd6739e1182312382ab03e83b75f",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=680fe73ca28e1639a3b2337a68d83324e03742679e612a52d3d29c9b6fc4b512",
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
    assert auth2.include_headers == set()

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
            "cusTom",
            "x-aMz-client-context",
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
            " cusTom ",
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
            "cusTom",
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


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_header_performances_with_spaces_in_value(
    httpx_mock: HTTPXMock,
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        include_headers=[
            "custom_with_spaces",
        ],
    )

    header_value = "test with  spaces" * 100_000

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=custom_with_spaces;host;x-amz-content-sha256;x-amz-date, Signature=ea0663a29c9f4a5225d9e882121e5c3744321c12b07ce5e6d4e7081b2e26ad8b",
            "x-amz-date": "20181011T150505Z",
            "custom_with_spaces": header_value,
        },
    )

    with httpx.Client() as client:
        start = time.perf_counter_ns()
        client.get(
            "https://authorized_only",
            headers={"custom_with_spaces": header_value},
            auth=auth,
        )
        end = time.perf_counter_ns()

    assert end - start < 5_000_000_000


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_header_performances_without_spaces_in_value(
    httpx_mock: HTTPXMock,
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        include_headers=[
            "custom_without_spaces",
        ],
    )

    header_value = "testwithoutspaces" * 100_000

    httpx_mock.add_response(
        url="https://authorized_only",
        method="GET",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=custom_without_spaces;host;x-amz-content-sha256;x-amz-date, Signature=bd17043b2133cd88f271ddc8248b59f31ed45cf73122dd68f931d4e87ecfca3d",
            "x-amz-date": "20181011T150505Z",
            "custom_without_spaces": header_value,
        },
    )

    with httpx.Client() as client:
        start = time.perf_counter_ns()
        client.get(
            "https://authorized_only",
            headers={"custom_without_spaces": header_value},
            auth=auth,
        )
        end = time.perf_counter_ns()

    assert end - start < 30_000_000


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
            "226515100ad91c335cd215dd918807637b6f24c6ce83679f988ad953e2b80010",
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
            "My-Header1",
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
    )

    httpx_mock.add_response(
        url="https://authorized_only:8443",
        method="GET",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=6c4d64151fab428de4853175fe4dcef1a0c5e247741cc1095553627cc0234857",
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
            "x-amz-content-sha256": "1e1d3e3fb0bcfb7b2b61f687369d0227e6aefd6739e1182312382ab03e83b75f",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=838d461dd62852877565b9f91558a9da26d7af50d8fadf3c48cc1a9f6d3561f4",
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
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=b9d25c292a0306ac3be08a34c04d694448ddc34dcd28654303d28e24a6ba3df3",
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
    "decoded_value, encoded_value, signature",
    [
        [
            "a&b",
            "a%26b",
            "db0909a13cb56b574ea0c828a2875537a90ce7bed00e8237b817b4211adb8662",
        ],
        [
            "a=b",
            "a%3Db",
            "e4e0fb580cb9b304f6fb5f7e9294156fb1b17f0d23a79e6ccfa86ec8120a5c7e",
        ],
        [
            "a+b",
            "a%2Bb",
            "a69fde859c7ba14634f827bdbfce8e558709b26e5eceb2e507e99430ba8e79df",
        ],
        [
            "a b",
            "a%20b",
            "6eef487def6c062806b89437027e12f641f35e1dfda5cc7ae49da777ad5f0fb4",
        ],
        [
            "/?a=b&c=d",
            "/%3Fa%3Db%26c%3Dd",
            "e57ce6433a7158380da02ee7afbcf7adca26e3b61ff46f80816453f932e67ccc",
        ],
    ],
)
@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_query_parameters_encoded_values(
    httpx_mock: HTTPXMock, decoded_value: str, encoded_value: str, signature: str
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url=f"https://authorized_only?foo={encoded_value}&bar=1",
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
        url="https://authorized_only/?@$%25%5E&+=/,?%3E%3C%60%22;:%5C%7C][%7B%7D%20=@$%25%5E&+=/,?%3E%3C%60%22;:%5C%7C][%7B%7D",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=023c011b36e5f048578ebf41c04f550a6db3437cf0c8fc491184f44ef8e7e212",
            "x-amz-date": "20181011T150505Z",
        },
    )

    with httpx.Client() as client:
        client.post(
            r'https://authorized_only/?@$%^&+=/,?><`";:\|][{} =@$%^&+=/,?><`";:\|][{}',
            auth=auth,
        )


@time_machine.travel("2018-10-11T15:05:05.663979+00:00", tick=False)
def test_aws_auth_query_reserved_with_fragment(httpx_mock: HTTPXMock):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )

    httpx_mock.add_response(
        url=r'https://authorized_only/?@#$%^&+=/,?%3E%3C`";:\|][{}%20=@#$%^&+=/,?%3E%3C`";:\|][{}',
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=73a30ab39b554b5d6b2d0e6b575b4d108794334a532068a2e388027e7914288f",
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
        url="https://authorized_only?foo=value;bar=1",
        method="GET",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=d8d77276658fbe9b7715811c0d55d34b545789cacfb8735fad8946d20ff74f37",
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
        url="https://authorized_only/test/hello-*.&^~+{}!$%C2%A3_%20",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=04a5225313f4ffc8a8f4a974ad9c8d29a02df6ce0dabda1898ba1cccf2a3fb56",
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
        url="https://authorized_only/test/%2a%2b%25/~-_^&%20%%",
        method="POST",
        match_headers={
            "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=9e643e5c1a494c954b28c0ad986b9343e70b02df2bdaddee7f7b2510073ae16c",
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
        url="https://authorized_only/test/%2a%2b%25/~-_^& %%",
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
