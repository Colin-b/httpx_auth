import datetime

import pytest
from pytest_httpx import HTTPXMock
import httpx

import httpx_auth

# def request_from_text(text):
#     """
#     Construct a Requests PreparedRequest using values provided in text.
#     text should be a plaintext HTTP request, as defined in RFC7230.
#     """
#     lines = text.splitlines()
#     match = re.search("^([a-z]+) (.*) (http/[0-9].[0-9])$", lines[0], re.I)
#     method, path, version = match.groups()
#     headers = {}
#     for idx, line in enumerate(lines[1:], start=1):
#         if not line:
#             break
#         hdr, val = [item.strip() for item in line.split(":", 1)]
#         hdr = hdr.lower()
#         vals = headers.setdefault(hdr, [])
#         vals.append(val)
#     headers = {hdr: ",".join(sorted(vals)) for hdr, vals in headers.items()}
#     check_url = urlparse(path)
#     if check_url.scheme and check_url.netloc:
#         # absolute URL in path
#         url = path
#     else:
#         # otherwise need to try to construct url from path and host header
#         url = "".join(
#             ["http://" if "host" in headers else "", headers.get("host", ""), path]
#         )
#     body = "\n".join(lines[idx + 1 :])
#     req = httpx.Request(method, url, headers=headers, data=body)
#     # ensure content field is useable
#     req.read()
#     return req
#
#
#
# class AWS4Auth_AmzCanonicalQuerystring_Test(unittest.TestCase):
#     def setUp(self):
#         self.auth = AWS4Auth("id", "secret", "us-east-1", "es")
#
#     def test_basic(self):
#         qs = "greet=hello"
#         encoded = self.auth.amz_cano_querystring(qs)
#         self.assertEqual(encoded, qs)
#
#     def test_multiple_params(self):
#         qs = "greet=hello&impression=wtf"
#         encoded = self.auth.amz_cano_querystring(qs)
#         self.assertEqual(encoded, qs)
#
#     def test_space(self):
#         """
#         Test space in the querystring. See post-vanilla-query-space test in the
#         downloadable amz testsuite for expected behaviour.
#         """
#         qs = "greet=hello&impression =wtf"
#         expected = "greet=hello&impression="
#         encoded = self.auth.amz_cano_querystring(qs)
#         self.assertEqual(encoded, expected)
#
#     def test_quoting(self):
#         qs = 'greet=hello&impression=!#"£$%^*()-_@~{},.<>/\\'
#         expected = "greet=hello&impression=%21%23%22%C2%A3%24%25%5E%2A%28%29-_%40~%7B%7D%2C.%3C%3E%2F%5C"
#         encoded = self.auth.amz_cano_querystring(qs)
#         self.assertEqual(encoded, expected)
#
#
# class AWS4Auth_GetCanonicalHeaders_Test(unittest.TestCase):
#     def test_headers_amz_example(self):
#         """
#         Using example from:
#         http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
#         """
#         hdr_text = [
#             "host:iam.amazonaws.com",
#             "Content-type:application/x-www-form-urlencoded; charset=utf-8",
#             "My-header1:    a   b   c ",
#             "x-amz-date:20120228T030031Z",
#             'My-Header2:    "a   b   c"',
#             "user-agent:python-httpx",
#         ]
#         headers = dict([item.split(":") for item in hdr_text])
#         req = httpx.Request("GET", "http://iam.amazonaws.com", headers=headers)
#         include = list(req.headers)
#         result = AWS4Auth.get_canonical_headers(req, include=include)
#         cano_headers, signed_headers = result
#         expected = [
#             "accept:*/*",
#             "accept-encoding:gzip, deflate",
#             "connection:keep-alive",
#             "content-type:application/x-www-form-urlencoded; charset=utf-8",
#             "host:iam.amazonaws.com",
#             "my-header1:a b c",
#             'my-header2:"a   b   c"',
#             "user-agent:python-httpx",
#             "x-amz-date:20120228T030031Z",
#         ]
#         expected = "\n".join(expected) + "\n"
#         self.assertEqual(cano_headers, expected)
#         expected = "accept;accept-encoding;connection;content-type;host;my-header1;my-header2;user-agent;x-amz-date"
#         self.assertEqual(signed_headers, expected)
#
#     def test_no_host_header(self):
#         hdr_text = [
#             "Content-type:application/x-www-form-urlencoded; charset=utf-8",
#             "Host:iam.amazonaws.com",
#             "My-header1:    a   b   c ",
#             "x-amz-date:20120228T030031Z",
#             'My-Header2:    "a   b   c"',
#             "user-agent:python-httpx",
#         ]
#         headers = dict([item.split(":") for item in hdr_text])
#         req = httpx.Request("GET", "http://iam.amazonaws.com", headers=headers)
#         include = list(req.headers)
#         # remove host for test
#         if "host" in req.headers:
#             del req.headers["host"]
#         result = AWS4Auth.get_canonical_headers(req, include=include)
#         cano_headers, signed_headers = result
#         expected = [
#             "accept:*/*",
#             "accept-encoding:gzip, deflate",
#             "connection:keep-alive",
#             "content-type:application/x-www-form-urlencoded; charset=utf-8",
#             "host:iam.amazonaws.com",
#             "my-header1:a b c",
#             'my-header2:"a   b   c"',
#             "user-agent:python-httpx",
#             "x-amz-date:20120228T030031Z",
#         ]
#         expected = "\n".join(expected) + "\n"
#         self.assertEqual(cano_headers, expected)
#         expected = "accept;accept-encoding;connection;content-type;host;my-header1;my-header2;user-agent;x-amz-date"
#         self.assertEqual(signed_headers, expected)
#
#     def test_duplicate_headers(self):
#         """
#         Tests case of duplicate headers with different cased names. Uses a
#         mock Request object with regular dict to hold headers, since Requests
#         PreparedRequest dict is case-insensitive.
#         """
#         class SimpleNamespace:
#             pass
#         req = SimpleNamespace()
#         req.headers = {
#             "ZOO": "zoobar",
#             "FOO": "zoobar",
#             "zoo": "foobar",
#             "Content-Type": "text/plain",
#             "host": "dummy",
#         }
#         include = [x for x in req.headers if x != "Content-Type"]
#         result = AWS4Auth.get_canonical_headers(req, include=include)
#         cano_headers, signed_headers = result
#         cano_expected = "foo:zoobar\nhost:dummy\nzoo:foobar,zoobar\n"
#         signed_expected = "foo;host;zoo"
#         self.assertEqual(cano_headers, cano_expected)
#         self.assertEqual(signed_headers, signed_expected)
#
#     def test_netloc_port(self):
#         """
#         Test that change in d190dcb doesn't regress - strip port from netloc
#         before generating signature - httpx.Request always has a host header
#         """
#         req = httpx.Request("GET", "http://amazonaws.com:8443")
#         result = AWS4Auth.get_canonical_headers(req)
#         cano_hdrs, signed_hdrs = result
#         expected = "host:amazonaws.com:8443\n"
#         self.assertEqual(cano_hdrs, expected)
#
#
# class AWS4Auth_GetCanonicalRequest_Test(unittest.TestCase):
#     def test_amz1(self):
#         """
#         Using example data selected from:
#         http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
#         """
#         req_text = [
#             "POST https://iam.amazonaws.com/ HTTP/1.1",
#             "Host: iam.amazonaws.com",
#             "Content-Length: 54",
#             "Content-Type: application/x-www-form-urlencoded",
#             "X-Amz-Date: 20110909T233600Z",
#             "",
#             "Action=ListUsers&Version=2010-05-08",
#         ]
#         req = request_from_text("\n".join(req_text))
#         hsh = hashlib.sha256(req.content)
#         req.headers["x-amz-content-sha256"] = hsh.hexdigest()
#         include_hdrs = ["host", "content-type", "x-amz-date"]
#         result = AWS4Auth.get_canonical_headers(req, include=include_hdrs)
#         cano_headers, signed_headers = result
#         expected = [
#             "POST",
#             "/",
#             "",
#             "content-type:application/x-www-form-urlencoded",
#             "host:iam.amazonaws.com",
#             "x-amz-date:20110909T233600Z",
#             "",
#             "content-type;host;x-amz-date",
#             "b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2",
#         ]
#         expected = "\n".join(expected)
#         auth = AWS4Auth("dummy", "dummy", "dummy", "host")
#         cano_req = auth.get_canonical_request(req, cano_headers, signed_headers)
#         self.assertEqual(cano_req, expected)
#
#
# class AWS4Auth_RequestSign_Test(unittest.TestCase):
#     def test_generate_signature(self):
#         """
#         Using example data from
#         http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
#         """
#         secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
#         region = "us-east-1"
#         service = "iam"
#         date = "20110909"
#         key = AWS4SigningKey(secret_key, region, service, date)
#         req_text = [
#             "POST https://iam.amazonaws.com/ HTTP/1.1",
#             "Host: iam.amazonaws.com",
#             "Content-Type: application/x-www-form-urlencoded; charset=utf-8",
#             "User-Agent:python-httpx",
#             "X-Amz-Date: 20110909T233600Z",
#             "",
#             "Action=ListUsers&Version=2010-05-08",
#         ]
#         req_text = "\n".join(req_text) + "\n"
#         req = request_from_text(req_text)
#         del req.headers["content-length"]
#         include_hdrs = list(req.headers)
#         auth = AWS4Auth("dummy", key, include_hdrs=include_hdrs)
#         hsh = hashlib.sha256(req.content)
#         req.headers["x-amz-content-sha256"] = hsh.hexdigest()
#         sreq = next(auth.auth_flow(req))
#         signature = sreq.headers["Authorization"].split("=")[3]
#         expected = "d50ec75eed10aeb2cb3ddf6702d65d3bce310464d99da6f1af092bbc0f238295"
#         self.assertEqual(signature, expected)
#
#     def test_generate_empty_body_signature(self):
#         """
#         Check that change in af03ce5 doesn't regress - ensure request body is
#         not altered by signing process if it is empty (i.e None).
#         """
#         auth = AWS4Auth("x", "x", "us-east-1", "s3")
#         req = httpx.Request("GET", "http://amazonaws.com", data=None)
#         sreq = next(auth.auth_flow(req))
#         signature = sreq.headers["Authorization"].split("=")[3]
#         self.assertIsNotNone(signature)
#
#     def test_regen_key_on_date_mismatch(self):
#         vals = [
#             ("20001231T235959Z", "20010101"),
#             ("20000101T010101Z", "20000102"),
#             ("19900101T010101Z", "20000101"),
#         ]
#         for amzdate, scope_date in vals:
#             req = httpx.Request("GET", "http://blah.com")
#             if "date" in req.headers:
#                 del req.headers["date"]
#             req.headers["x-amz-date"] = amzdate
#             secret_key = "dummy"
#             region = "us-east-1"
#             service = "iam"
#             date = scope_date
#             key = AWS4SigningKey(secret_key, region, service, date)
#             orig_id = id(key)
#             auth = AWS4Auth("dummy", key)
#             sreq = next(auth.auth_flow(req))
#             self.assertNotEqual(id(auth.signing_key), orig_id)
#             self.assertEqual(auth.date, amzdate.split("T")[0])
#
#     @staticmethod
#     def check_auth(auth, req):
#         sreq = next(auth.auth_flow(req))
#
#     def test_raise_date_mismatch_error_on_date_mismatch(self):
#
#         amzdate, scope_date = ("20001231T235959Z", "20010101")
#         req = httpx.Request("GET", "http://blah.com")
#         if "date" in req.headers:
#             del req.headers["date"]
#         req.headers["x-amz-date"] = amzdate
#         secret_key = "dummy"
#         region = "us-east-1"
#         service = "iam"
#         date = scope_date
#         key = AWS4SigningKey(secret_key, region, service, date)
#         orig_id = id(key)
#         auth = StrictAWS4Auth("dummy", key)
#         self.assertRaises(DateMismatchError, self.check_auth, auth, req)
#
#     def test_date_mismatch_nosecretkey_raise(self):
#         key = AWS4SigningKey("secret_key", "region", "service", "1999010", False)
#         auth = AWS4Auth("access_id", key)
#         req = httpx.Request("GET", "http://blah.com")
#         if "date" in req.headers:
#             del req.headers["date"]
#         req.headers["x-amz-date"] = "20000101T010101Z"
#         self.assertRaises(NoSecretKeyError, self.check_auth, auth, req)
#
#     def test_sts_creds_include_security_token_header(self):
#         key = AWS4SigningKey("secret_key", "region", "service", "1999010")
#         auth = AWS4Auth("access_id", key, session_token="sessiontoken")
#         req = httpx.Request("GET", "http://blah.com")
#         sreq = next(auth.auth_flow(req))
#         self.assertIn("x-amz-security-token", sreq.headers)
#         self.assertEqual(sreq.headers.get("x-amz-security-token"), "sessiontoken")
#
@pytest.fixture
def mock_aws_datetime(monkeypatch):
    _date_time_for_tests = datetime.datetime(2018, 10, 11, 15, 5, 5, 663979)

    class DateTimeModuleMock:
        class DateTimeMock:
            @staticmethod
            def utcnow():
                return _date_time_for_tests

        datetime = DateTimeMock

    import httpx_auth.aws

    monkeypatch.setattr(httpx_auth.aws, "datetime", DateTimeModuleMock)


def test_aws_auth_with_empty_secret_key(httpx_mock: HTTPXMock, mock_aws_datetime):
    with pytest.raises(Exception) as exception_info:
        httpx_auth.AWS4Auth(
            access_id="access_id", secret_key="", region="us-east-1", service="iam"
        )
    assert str(exception_info.value) == "Secret key is mandatory."


def test_aws_auth_without_content_in_request(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(url="http://authorized_only")

    httpx.post("http://authorized_only", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=ce708380ee69b1a9558b9b0dddd4d15f35a2a5e5ea3534b541247f1a746626db"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_with_content_in_request(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(url="http://authorized_only")

    httpx.post("http://authorized_only", json=[{"key": "value"}], auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "fb65c1441d6743274738fe3b3042a73167ba1fb2d34679d8dd16433473758f97"
    )
    assert (
        headers["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=5f4f832a19fc834d4f34047289ad67d96da25bd414a70f02ce6b85aef9ab8068"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_with_security_token_and_without_content_in_request(
    httpx_mock: HTTPXMock, mock_aws_datetime
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        security_token="security_token",
    )
    httpx_mock.add_response(url="http://authorized_only")

    httpx.post("http://authorized_only", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=2ae27ce5e8dcc005736c97ff857e4f44401fc3a33d8358b1d67c079f0f5a8b3e"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"
    assert headers["x-amz-security-token"] == "security_token"


def test_aws_auth_with_security_token_and_content_in_request(
    httpx_mock: HTTPXMock, mock_aws_datetime
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        security_token="security_token",
    )
    httpx_mock.add_response(url="http://authorized_only")

    httpx.post("http://authorized_only", json=[{"key": "value"}], auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "fb65c1441d6743274738fe3b3042a73167ba1fb2d34679d8dd16433473758f97"
    )
    assert (
        headers["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=e02c4733589cf6e80361f6905564da6d0c23a0829bb3c3899b328e43b2f7b581"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"
    assert headers["x-amz-security-token"] == "security_token"


def test_aws_auth_override_x_amz_date_header(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(url="http://authorized_only")

    httpx.post(
        "http://authorized_only", headers={"x-amz-date": "20201011T150505Z"}, auth=auth
    )
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=ce708380ee69b1a9558b9b0dddd4d15f35a2a5e5ea3534b541247f1a746626db"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_root_path(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(url="http://authorized_only")

    httpx.post("http://authorized_only/", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=ce708380ee69b1a9558b9b0dddd4d15f35a2a5e5ea3534b541247f1a746626db"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_query_parameters(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(url="http://authorized_only?param1&param2=blah*")

    httpx.post("http://authorized_only?param1&param2=blah*", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=f2b8a73e388dc04586b5bcc208c6e50d92f04a1296e561229cd88811ad2494e9"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_path_normalize(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(url="http://authorized_only/stuff//more/")

    httpx.post("http://authorized_only/./test/../stuff//more/", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=e49fb885d30c9e74901071748b783fabe8ba7a979aa20420ac76af1dda1edd03"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_path_quoting(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(
        url="http://authorized_only/test/hello-*.&%5E%7E+%7B%7D!$%C2%A3_%20"
    )

    httpx.post("http://authorized_only/test/hello-*.&^~+{}!$£_ ", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=98dd3cdd2a603907495164f08fe7197fb405bf8c556ddf7b88d7e15341a9588a"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_path_percent_encode_non_s3(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(
        url="http://authorized_only/test/%252a%252b%2525/%7E-_%5E&%20%25%25"
    )

    httpx.post("http://authorized_only/test/%2a%2b%25/~-_^& %%", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=1da6c689b7a20044144a9f265ddecc38b1b884902846fbe4dc8049595f25565f"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_path_percent_encode_s3(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="s3",
    )
    httpx_mock.add_response(
        url="http://authorized_only/test/%252a%252b%2525/%7E-_%5E&%20%25%25"
    )

    httpx.post("http://authorized_only/test/%2a%2b%25/~-_^& %%", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=2fc7c2f27151e18348862bab0bbe90c4a9f29d7863a33e725d7b1ec96709fdd6"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"

def test_aws_auth_without_path(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(url="http://authorized_only")

    httpx.get("http://authorized_only", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=access_id/20181011/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=e3411118ac098a820690144b8b273aa64a3366d899fa68fd64a1ab950c982b4b"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"

def test_amz_cano_path_empty_path():
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    cano_path = auth.amz_cano_path("")
    assert cano_path == "/"
