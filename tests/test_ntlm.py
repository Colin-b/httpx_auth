import sys
from typing import Optional, List
from pytest_httpx import HTTPXMock
from httpx_auth import Negotiate
from collections import namedtuple

import httpx
import pytest

spnego = pytest.importorskip("spnego")

TEST_USER = "test_user"
TEST_PASS = "test_pass"
TEST_URL = "https://www.example.com/test"

FLOW_CHALLENGE_RESPONSE = "NTLM CAkKCwwNDg8="
FLOW_AUTHENTICATE_REQUEST = "NTLM AAECAwQFBgc="
FLOW_AUTHORIZATION_RESPONSE = "NTLM Dw4NDAsKCQg="

MockDefinition = namedtuple(
    "mock_definition", ("url", "status_code", "match_headers", "headers")
)
MockDefinition.__new__.__defaults__ = ("", 0, {}, {})


@pytest.fixture
def negotiate_auth_fixture():
    yield Negotiate(TEST_USER, TEST_PASS)


class TestNegotiateUnit:
    bytes_content = b"\x00\x01\x02\x03\x04\x05\x06\x07"
    str_content = "AAECAwQFBgc="

    def test_parse_auth_header_single_success(self, negotiate_auth_fixture):
        negotiate_auth_fixture.auth_type = "NTLM"

        header_value = f"NTLM {self.str_content}"
        actual_output = negotiate_auth_fixture._parse_authenticate_header(header_value)
        assert actual_output == self.bytes_content

    def test_parse_auth_header_multi_success(self, negotiate_auth_fixture):
        negotiate_auth_fixture.auth_type = "Negotiate"

        header_value = (
            f"Negotiate {self.str_content}, Basic dGVzdF91c2VyOnRlc3RfcGFzcw=="
        )
        actual_output = negotiate_auth_fixture._parse_authenticate_header(header_value)
        assert actual_output == self.bytes_content

    def test_parse_auth_header_single_fail(self, negotiate_auth_fixture):
        negotiate_auth_fixture.auth_type = "NTLM"

        header_value = f"Negotiate {self.str_content}"
        with pytest.raises(StopIteration):
            _ = negotiate_auth_fixture._parse_authenticate_header(header_value)

    @pytest.mark.parametrize("auth_type", ["NTLM", "Negotiate"])
    def test_make_auth_header(self, negotiate_auth_fixture, auth_type: str):
        expected_output = f"{auth_type} {self.str_content}"
        negotiate_auth_fixture.auth_type = auth_type
        actual_str = negotiate_auth_fixture._make_authorization_header(
            self.bytes_content
        )

        assert actual_str == expected_output

    @pytest.mark.parametrize(
        ["test_input", "expected_output"],
        [
            ("NTLM Successful", "NTLM"),
            ("NtLm Successful", "NTLM"),
            ("Negotiate Successful", "Negotiate"),
            ("NeGoTiATe Successful", "Negotiate"),
            ("Negotiate", "Negotiate"),
        ],
    )
    def test_auth_type_from_header(
        self, negotiate_auth_fixture, test_input: str, expected_output: Optional[str]
    ):
        actual_output = negotiate_auth_fixture._auth_type_from_header(test_input)
        assert actual_output.lower() == expected_output.lower()

    def test_auth_type_from_header_returns_none_when_not_ntlm(
        self, negotiate_auth_fixture
    ):
        header_content = "Basic Failure"
        actual_output = negotiate_auth_fixture._auth_type_from_header(header_content)
        assert actual_output is None

    def test_new_context_proxy(self, negotiate_auth_fixture):
        proxy = negotiate_auth_fixture._new_context_proxy()
        assert proxy.username == TEST_USER
        assert proxy.password == TEST_PASS
        assert proxy.protocol.lower() == "negotiate"
        assert spnego.NegotiateOptions.use_ntlm not in proxy.options
        assert proxy.spn.lower() == "host/unspecified"

    def test_new_context_proxy_with_ntlm(self, negotiate_auth_fixture):
        negotiate_auth_fixture.force_ntlm = True
        proxy = negotiate_auth_fixture._new_context_proxy()
        assert proxy.username == TEST_USER
        assert proxy.password == TEST_PASS
        assert proxy.protocol.lower() == "ntlm"
        assert spnego.NegotiateOptions.use_ntlm in proxy.options
        assert proxy.spn.lower() == "host/unspecified"

    def test_password_with_no_username_throws(self):
        with pytest.raises(ValueError) as exception_info:
            _ = Negotiate(password=TEST_PASS)
        assert "no username was provided" in str(exception_info)

    def test_ntlm_with_no_credentials_throws(self):
        with pytest.raises(ValueError) as exception_info:
            _ = Negotiate(force_ntlm=True)
        assert "provide a username and password" in str(exception_info)

    def test_no_spnego_package_is_handled(self):
        sys.modules['spnego'] = None
        from negotiate import Negotiate
        with pytest.raises(ImportError) as exception_info:
            _ = Negotiate()
        assert "Windows authentication support not enabled" in str(exception_info)


def mock_auth_responses(request_count: int):
    return [
        b"\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
        b"\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08",
    ] * request_count


def get_patch_method():
    if sys.platform == "win32":
        patch_object = "httpx_auth.negotiate.spnego.sspi.SSPIProxy.step"
    else:
        patch_object = "httpx_auth.negotiate.spnego.negotiate.NegotiateProxy.step"
    return patch_object


def make_mockery(httpx_mock: HTTPXMock, mockery_definition: List[namedtuple]) -> None:
    for mock_definition in mockery_definition:
        httpx_mock.add_response(
            url=mock_definition.url,
            status_code=mock_definition.status_code,
            match_headers=mock_definition.match_headers,
            headers=mock_definition.headers,
        )


class TestNegotiateFunctional:
    def test_http_200_response_makes_one_request(
        self, negotiate_auth_fixture, httpx_mock: HTTPXMock
    ):
        make_mockery(httpx_mock, [MockDefinition(TEST_URL, 200, {}, {})])
        with httpx.Client() as client:
            resp = client.get(
                url=TEST_URL,
                auth=negotiate_auth_fixture,
            )
            assert resp.status_code == 200
            assert len(httpx_mock.get_requests()) == 1

    def test_http_authenticate_with_digest_returns_401(
        self, negotiate_auth_fixture, httpx_mock: HTTPXMock
    ):
        make_mockery(
            httpx_mock,
            [MockDefinition(TEST_URL, 401, {}, {"WWW-Authenticate": "Digest"})],
        )
        with httpx.Client() as client:
            resp = client.get(
                url=TEST_URL,
                auth=negotiate_auth_fixture,
            )
            assert resp.status_code == 401
            assert len(resp.history) == 0
            assert len(httpx_mock.get_requests()) == 1

    def test_http_401s_make_three_requests_and_return_401(
        self, negotiate_auth_fixture, httpx_mock: HTTPXMock, mocker
    ):
        make_mockery(
            httpx_mock,
            [
                MockDefinition(TEST_URL, 401, {}, {"WWW-Authenticate": "NTLM"}),
                MockDefinition(
                    TEST_URL,
                    401,
                    {"Authorization": FLOW_CHALLENGE_RESPONSE},
                    {"WWW-Authenticate": FLOW_AUTHENTICATE_REQUEST},
                ),
            ],
        )

        with mocker.patch(
            get_patch_method(),
            side_effect=mock_auth_responses(1),
        ):
            with httpx.Client() as client:
                resp = client.get(
                    url=TEST_URL,
                    auth=negotiate_auth_fixture,
                )
                assert resp.status_code == 401
                assert len(resp.history) == 2
                assert len(httpx_mock.get_requests()) == 3

    def test_authentication_with_redirect_is_followed(
        self, negotiate_auth_fixture, httpx_mock: HTTPXMock, mocker
    ):
        redirect_url = TEST_URL + "/"
        make_mockery(
            httpx_mock,
            [
                MockDefinition(TEST_URL, 401, {}, {"WWW-Authenticate": "NTLM"}),
                MockDefinition(
                    TEST_URL,
                    401,
                    {"Authorization": FLOW_CHALLENGE_RESPONSE},
                    {"WWW-Authenticate": FLOW_AUTHENTICATE_REQUEST},
                ),
                MockDefinition(
                    TEST_URL,
                    301,
                    {"Authorization": FLOW_AUTHORIZATION_RESPONSE},
                    {"Location": redirect_url},
                ),
                MockDefinition(redirect_url, 401, {}, {"WWW-Authenticate": "NTLM"}),
                MockDefinition(
                    redirect_url,
                    401,
                    {"Authorization": FLOW_CHALLENGE_RESPONSE},
                    {"WWW-Authenticate": FLOW_AUTHENTICATE_REQUEST},
                ),
                MockDefinition(
                    redirect_url,
                    200,
                    {"Authorization": FLOW_AUTHORIZATION_RESPONSE},
                    {},
                ),
            ],
        )
        with mocker.patch(
            get_patch_method(),
            side_effect=mock_auth_responses(2),
        ):
            with httpx.Client() as client:
                resp = client.get(
                    url=TEST_URL,
                    auth=negotiate_auth_fixture,
                )
                assert resp.status_code == 200
                assert len(resp.history) == 4
                assert len(httpx_mock.get_requests()) == 6

    def test_authentication_with_too_many_redirects_throws(
        self, negotiate_auth_fixture, httpx_mock: HTTPXMock, mocker
    ):
        redirect_url = TEST_URL + "/"
        make_mockery(
            httpx_mock,
            [
                MockDefinition(TEST_URL, 401, {}, {"WWW-Authenticate": "NTLM"}),
                MockDefinition(
                    TEST_URL,
                    401,
                    {"Authorization": FLOW_CHALLENGE_RESPONSE},
                    {"WWW-Authenticate": FLOW_AUTHENTICATE_REQUEST},
                ),
                MockDefinition(
                    TEST_URL,
                    301,
                    {"Authorization": FLOW_AUTHORIZATION_RESPONSE},
                    {"Location": redirect_url},
                ),
                MockDefinition(redirect_url, 401, {}, {"WWW-Authenticate": "NTLM"}),
            ],
        )
        with mocker.patch(
            get_patch_method(),
            side_effect=mock_auth_responses(1),
        ):
            with httpx.Client() as client:
                auth = negotiate_auth_fixture
                auth.max_redirects = 0
                with pytest.raises(httpx.TooManyRedirects) as exception_info:
                    _ = client.get(
                        url=TEST_URL,
                        auth=auth,
                    )
                assert "Redirected too many times" in str(exception_info)
                assert "0" in str(exception_info)

    @pytest.mark.parametrize("status_code", [200, 403, 404])
    def test_http_response_reported_correctly_when_auth_completes(
        self, negotiate_auth_fixture, httpx_mock: HTTPXMock, mocker, status_code
    ):
        make_mockery(
            httpx_mock,
            [
                MockDefinition(TEST_URL, 401, {}, {"WWW-Authenticate": "NTLM"}),
                MockDefinition(
                    TEST_URL,
                    401,
                    {"Authorization": FLOW_CHALLENGE_RESPONSE},
                    {"WWW-Authenticate": FLOW_AUTHENTICATE_REQUEST},
                ),
                MockDefinition(
                    TEST_URL,
                    status_code,
                    {"Authorization": FLOW_AUTHORIZATION_RESPONSE},
                    {},
                ),
            ],
        )

        with mocker.patch(
            get_patch_method(),
            side_effect=mock_auth_responses(1),
        ):
            with httpx.Client() as client:
                resp = client.get(
                    url=TEST_URL,
                    auth=negotiate_auth_fixture,
                )
                assert resp.status_code == status_code
                assert len(resp.history) == 2
                assert len(httpx_mock.get_requests()) == 3

    def test_http_response_sets_cookie_if_required(
        self, negotiate_auth_fixture, httpx_mock: HTTPXMock, mocker
    ):
        test_cookie = "foo=bar"
        make_mockery(
            httpx_mock,
            [
                MockDefinition(TEST_URL, 401, {}, {"WWW-Authenticate": "NTLM"}),
                MockDefinition(
                    TEST_URL,
                    401,
                    {"Authorization": FLOW_CHALLENGE_RESPONSE},
                    {
                        "WWW-Authenticate": FLOW_AUTHENTICATE_REQUEST,
                        "Set-Cookie": test_cookie,
                    },
                ),
                MockDefinition(
                    TEST_URL,
                    200,
                    {
                        "Authorization": FLOW_AUTHORIZATION_RESPONSE,
                        "Cookie": test_cookie,
                    },
                    {},
                ),
            ],
        )
        with mocker.patch(
            get_patch_method(),
            side_effect=mock_auth_responses(1),
        ):
            with httpx.Client() as client:
                resp = client.get(
                    url=TEST_URL,
                    auth=negotiate_auth_fixture,
                )
                assert resp.status_code == 200
                assert len(resp.history) == 2
                assert len(httpx_mock.get_requests()) == 3
