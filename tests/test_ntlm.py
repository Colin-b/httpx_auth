import os
from functools import wraps
from typing import Optional

import httpx
import pytest
from pytest_httpx import HTTPXMock
from pytest_mock import mocker

from httpx_auth.authentication import NTLM, _AuthenticationTarget


class TestAuthenticationTargetUnit:
    @pytest.mark.parametrize(
        ["status_code", "expected_type"], [(401, 1), (407, 2), (403, 0)]
    )
    def test_from_status_code(self, status_code: int, expected_type: int):
        auth_target = _AuthenticationTarget.from_status_code(status_code)
        assert auth_target.value == expected_type

    @pytest.mark.parametrize(
        ["auth_target", "expected_output"],
        [
            (_AuthenticationTarget.WWW, "WWW-Authenticate"),
            (_AuthenticationTarget.PROXY, "Proxy-Authenticate"),
        ],
    )
    def test_challenge_header(
        self, auth_target: _AuthenticationTarget, expected_output: str
    ):
        actual_output = auth_target.challenge_header_name()
        assert actual_output.lower() == expected_output.lower()

    @pytest.mark.parametrize(
        ["auth_target", "expected_output"],
        [
            (_AuthenticationTarget.WWW, "Authorization"),
            (_AuthenticationTarget.PROXY, "Proxy-Authorization"),
        ],
    )
    def test_challenge_header(
        self, auth_target: _AuthenticationTarget, expected_output: str
    ):
        actual_output = auth_target.response_header_name()
        assert actual_output.lower() == expected_output.lower()


@pytest.fixture()
def ntlm_auth_fixture():
    yield NTLM("test_user", "test_pass")


class TestNTLMUnit:
    bytes_content = b"\x00\x01\x02\x03\x04\x05\x06\x07"
    str_content = "AAECAwQFBgc="

    def test_parse_auth_header_single_success(self, ntlm_auth_fixture):
        ntlm_auth_fixture.authenticate_type = "NTLM"

        header_value = "NTLM {}".format(self.str_content)
        actual_output = ntlm_auth_fixture._parse_ntlm_authenticate_header(header_value)
        assert actual_output == self.bytes_content

    def test_parse_auth_header_multi_success(self, ntlm_auth_fixture):
        ntlm_auth_fixture.authenticate_type = "Negotiate"

        header_value = "Negotiate {}, Basic dGVzdF91c2VyOnRlc3RfcGFzcw==".format(
            self.str_content
        )
        actual_output = ntlm_auth_fixture._parse_ntlm_authenticate_header(header_value)
        assert actual_output == self.bytes_content

    def test_parse_auth_header_single_fail(self, ntlm_auth_fixture):
        ntlm_auth_fixture.authenticate_type = "NTLM"

        header_value = "Negotiate {}".format(self.str_content)
        with pytest.raises(StopIteration):
            _ = ntlm_auth_fixture._parse_ntlm_authenticate_header(header_value)

    @pytest.mark.parametrize("auth_type", ["NTLM", "Negotiate"])
    def test_make_auth_header(self, ntlm_auth_fixture, auth_type: str):
        expected_output = "{} {}".format(auth_type, self.str_content)
        ntlm_auth_fixture.authenticate_type = auth_type
        actual_str = ntlm_auth_fixture._make_authorization_header(self.bytes_content)

        assert actual_str == expected_output

    @pytest.mark.parametrize(
        ["test_input", "expected_output"],
        [
            ("NTLM Successful", "NTLM"),
            ("NtLm Successful", "NTLM"),
            ("Negotiate Successful", "Negotiate"),
            ("NeGoTiATe Successful", "Negotiate"),
        ],
    )
    def test_auth_type_from_header(
        self, ntlm_auth_fixture, test_input: str, expected_output: Optional[str]
    ):
        actual_output = ntlm_auth_fixture._auth_type_from_header(test_input)
        assert actual_output.lower() == expected_output.lower()

    def test_auth_type_from_header_returns_none_when_not_ntlm(self, ntlm_auth_fixture):
        header_content = "Basic Failure"
        actual_output = ntlm_auth_fixture._auth_type_from_header(header_content)
        assert actual_output is None


def wrap_with_workstation(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            current_workstation = os.environ["NETBIOS_COMPUTER_NAME"]
        except KeyError:
            current_workstation = None
        os.environ["NETBIOS_COMPUTER_NAME"] = "TESTWORKSTATION"
        func(self, *args, **kwargs)
        if current_workstation is not None:
            os.environ["NETBIOS_COMPUTER_NAME"] = current_workstation
        else:
            del os.environ["NETBIOS_COMPUTER_NAME"]

    return wrapper


class TestNTLMFunctional:
    def test_http_200_response_makes_one_request(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url="https://www.example.com/test", status_code=200)

        with httpx.Client() as client:
            resp = client.get(
                url="https://www.example.com/test", auth=NTLM("test_user", "test_pass")
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

        mocker.patch(
            "httpx_auth.authentication.NTLMProxy.step",
            return_value=b"\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
        )

        with httpx.Client() as client:
            resp = client.get(
                url="https://www.example.com/test", auth=NTLM("test_user", "test_pass")
            )
            assert resp.status_code == 401
            assert len(resp.history) == 2
            assert len(httpx_mock.get_requests()) == 3

    def test_http_407s_make_three_requests_and_return_407(
        self, httpx_mock: HTTPXMock, mocker
    ):
        httpx_mock.add_response(
            status_code=407, headers={"Proxy-Authenticate": "Negotiate"}
        )
        httpx_mock.add_response(
            status_code=407,
            headers={"Proxy-Authenticate": "Negotiate AAECAwQFBgc="},
            match_headers={"Proxy-Authorization": "Negotiate CAkKCwwNDg8="},
        )

        mocker.patch(
            "httpx_auth.authentication.NTLMProxy.step",
            return_value=b"\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
        )

        with httpx.Client() as client:
            resp = client.get(
                url="https://www.example.com/test", auth=NTLM("test_user", "test_pass")
            )
            assert resp.status_code == 407
            assert len(resp.history) == 2
            assert len(httpx_mock.get_requests()) == 3

    @wrap_with_workstation
    @pytest.mark.parametrize("status_code", [200, 401, 403])
    def test_valid_handshake_returns_final_status(
        self, httpx_mock, mocker, status_code: int
    ):
        expect1 = {"Authorization": "NTLM TlRMTVNTUAABAAAAN4II4AAAAAAgAAAAAAAAACAAAAA="}
        response1 = {
            "WWW-Authenticate": "NTLM TlRMTVNTUAACAAAAHgAeADgAAAA1gori1CEifyE0ovkAAAAAAAAAAJgAmABWAAAACgBh"
            "SgAAAA9UAEUAUwBUAFcATwBSAEsAUwBUAEEAVABJAE8ATgACAB4AVABFAFMAVABXAE8AUgBLAFMAVABBAFQASQBPAE4AA"
            "QAeAFQARQBTAFQAVwBPAFIASwBTAFQAQQBUAEkATwBOAAQAHgBUAEUAUwBUAFcATwBSAEsAUwBUAEEAVABJAE8ATgADAB"
            "4AVABFAFMAVABXAE8AUgBLAFMAVABBAFQASQBPAE4ABwAIADbWHPMoRNcBAAAAAA=="
        }
        expect2 = {
            "Authorization": "NTLM TlRMTVNTUAADAAAAGAAYAFgAAADwAPAAcAAAAAAAAABgAQAAEAAQAGABAAAeAB4AcAEAAAgAC"
            "ACOAQAANYKK4gABBgAAAAAPw38elkNrZcKFdMx/yneDWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACSQFWteoy7KhaGzllQe"
            "8OIBAQAAAAAAADbWHPMoRNcB3q2+796tvu8AAAAAAgAeAFQARQBTAFQAVwBPAFIASwBTAFQAQQBUAEkATwBOAAEAHgBUAEU"
            "AUwBUAFcATwBSAEsAUwBUAEEAVABJAE8ATgAEAB4AVABFAFMAVABXAE8AUgBLAFMAVABBAFQASQBPAE4AAwAeAFQARQBTAF"
            "QAVwBPAFIASwBTAFQAQQBUAEkATwBOAAcACAA21hzzKETXAQkAHABIAE8AUwBUAC8AbABvAGMAYQBsAGgAbwBzAHQABgAEA"
            "AIAAAAAAAAAAAAAAEkASQBTAF8AVABlAHMAdABUAEUAUwBUAFcATwBSAEsAUwBUAEEAVABJAE8ATgCbo4V5ivHWOA=="
        }

        # Mock os.urandom since the client challenge is generated for the AUTHENTICATE message with 8 bytes of random
        # date
        mocker.patch(
            "httpx_auth.authentication.os.urandom",
            return_value=b"\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF",
        )

        httpx_mock.add_response(
            url="https://localhost/test",
            status_code=401,
            headers={"WWW-Authenticate": "NTLM"},
        )
        httpx_mock.add_response(
            url="https://localhost/test",
            status_code=401,
            headers=response1,
            match_headers=expect1,
        )
        httpx_mock.add_response(
            url="https://localhost/test", status_code=status_code, match_headers=expect2
        )

        with httpx.Client() as client:
            resp = client.get(
                url="https://localhost/test", auth=NTLM("IIS_Test", "rosebud")
            )
            print(resp.request.headers["Authorization"])
            assert resp.status_code == status_code
            assert len(resp.history) == 2
            assert len(httpx_mock.get_requests()) == 3
