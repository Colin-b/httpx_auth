import sys
from typing import Optional

import httpx
import pytest
spnego = pytest.importorskip('spnego')
from pytest_httpx import HTTPXMock

from httpx_auth.authentication import Negotiate


TEST_USER = "test_user"
TEST_PASS = "test_pass"


@pytest.fixture()
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


class TestNegotiateFunctional:
    def test_http_200_response_makes_one_request(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://www.example.com/test", status_code=200)

        with httpx.Client() as client:
            resp = client.get(
                url="https://www.example.com/test",
                auth=Negotiate("test_user", "test_pass"),
            )
            assert resp.status_code == 200
            assert len(httpx_mock.get_requests()) == 1

    def test_http_401s_make_three_requests_and_return_401(
        self, httpx_mock: HTTPXMock, mocker
    ):
        httpx_mock.add_response(status_code=401, headers={"WWW-Authenticate": "NTLM"})
        httpx_mock.add_response(
            status_code=401,
            headers={"WWW-Authenticate": "NTLM AAECAwQFBgc="},
            match_headers={"Authorization": "NTLM CAkKCwwNDg8="},
        )

        if sys.platform == "nt":
            patch_object = "httpx_auth.authentication.spnego.sspi.SSPIProxy.step"
        else:
            patch_object = "httpx_auth.authentication.spnego.gss.GSSAPIProxy.step"
        with mocker.patch(
            patch_object,
            return_value=b"\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
        ):
            with httpx.Client() as client:
                resp = client.get(
                    url="https://www.example.com/test",
                    auth=Negotiate("test_user", "test_pass"),
                )
                assert resp.status_code == 401
                assert len(resp.history) == 2
                assert len(httpx_mock.get_requests()) == 3
