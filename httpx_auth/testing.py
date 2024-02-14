import urllib.request
import threading
from urllib.parse import urlsplit
from typing import Dict, Optional
import datetime

import pytest

import httpx_auth
import httpx_auth._oauth2.authentication_responses_server
from httpx_auth._oauth2.authentication_responses_server import GrantDetails


def create_token(expiry: Optional[datetime.datetime]) -> str:
    import jwt  # Consider jwt an optional dependency for testing

    return jwt.encode({"exp": expiry}, "secret") if expiry else jwt.encode({}, "secret")


@pytest.fixture
def token_cache() -> httpx_auth.TokenMemoryCache:
    yield httpx_auth.OAuth2.token_cache
    httpx_auth.OAuth2.token_cache.clear()


class Tab(threading.Thread):
    def __init__(
        self,
        reply_url: str,
        data: str,
        success_template: Optional[str] = None,
        failure_template: Optional[str] = None,
    ):
        self.reply_url = reply_url
        self.data = data.encode() if data is not None else None
        self.checked = False
        self.success_template = (
            success_template or GrantDetails.DEFAULT_SUCCESS_TEMPLATE
        )
        self.failure_template = (
            failure_template or GrantDetails.DEFAULT_FAILURE_TEMPLATE
        )
        super().__init__()

    def run(self) -> None:
        if not self.reply_url:
            self.checked = True
            return

        self._request_favicon()
        self.content = self._simulate_redirect().decode()

    def _request_favicon(self):
        scheme, netloc, *_ = urlsplit(self.reply_url)
        favicon_response = urllib.request.urlopen(f"{scheme}://{netloc}/favicon.ico")
        assert favicon_response.read() == b"Favicon is not provided."

    def _simulate_redirect(self) -> bytes:
        content = urllib.request.urlopen(self.reply_url, data=self.data).read()
        if (
            content
            == b'<html><body><script>\n        var new_url = window.location.href.replace("#","?");\n        if (new_url.indexOf("?") !== -1) {\n            new_url += "&httpx_auth_redirect=1";\n        } else {\n            new_url += "?httpx_auth_redirect=1";\n        }\n        window.location.replace(new_url)\n        </script></body></html>'
        ):
            content = self._simulate_httpx_auth_redirect()
        return content

    def _simulate_httpx_auth_redirect(self) -> bytes:
        reply_url = self.reply_url.replace("#", "?")
        reply_url += (
            "&httpx_auth_redirect=1" if "?" in reply_url else "?httpx_auth_redirect=1"
        )
        return urllib.request.urlopen(reply_url, data=self.data).read()

    def assert_success(self, expected_message: str, timeout: int = 1):
        self.join()
        assert self.content == self.success_template.format(
            display_time=timeout, text=expected_message
        )
        self.checked = True

    def assert_failure(self, expected_message: str, timeout: int = 5000):
        self.join()
        assert self.content == self.failure_template.format(
            display_time=timeout, text=expected_message
        )
        self.checked = True


class BrowserMock:
    def __init__(self):
        self.tabs: Dict[str, Tab] = {}

    def open(self, url: str, new: int) -> bool:
        assert new == 1
        assert url in self.tabs, f"Browser call on {url} was not mocked."
        # Simulate a browser by sending the response in another thread
        self.tabs[url].start()
        return True

    def add_response(
        self,
        opened_url: str,
        reply_url: Optional[str],
        data: str = None,
        success_template: Optional[str] = None,
        failure_template: Optional[str] = None,
    ) -> Tab:
        """
        :param opened_url: URL opened by httpx_auth
        :param reply_url: The URL to send a response to, None to simulate the fact that there is no redirect.
        :param data: Body of the POST response to be sent. None to send a GET request.
        :success_template: Success template
        :failure_template: Failure template
        """
        tab = Tab(
            reply_url,
            data,
            success_template=success_template,
            failure_template=failure_template,
        )
        self.tabs[opened_url] = tab
        return tab

    def assert_checked(self):
        for url, tab in self.tabs.items():
            tab.join()
            assert tab.checked, f"Response received on {url} was not checked properly."


@pytest.fixture
def browser_mock(monkeypatch) -> BrowserMock:
    mock = BrowserMock()

    monkeypatch.setattr(
        httpx_auth._oauth2.authentication_responses_server.webbrowser,
        "get",
        lambda *args: mock,
    )
    yield mock
    mock.assert_checked()


@pytest.fixture
def token_mock() -> str:
    return "2YotnFZFEjr1zCsicMWpAA"


@pytest.fixture
def token_cache_mock(monkeypatch, token_mock: str):
    class TokenCacheMock:
        def get_token(self, *args, **kwargs) -> str:
            return token_mock

    monkeypatch.setattr(httpx_auth.OAuth2, "token_cache", TokenCacheMock())
