import urllib.request
import threading
from urllib.parse import urlsplit
from typing import Dict, Optional
import datetime

import pytest

import httpx_auth


def create_token(expiry: Optional[datetime.datetime]) -> str:
    import jwt  # Consider jwt an optional dependency for testing

    token = (
        jwt.encode({"exp": expiry}, "secret") if expiry else jwt.encode({}, "secret")
    )
    return token.decode("unicode_escape")


@pytest.fixture
def token_cache():
    yield httpx_auth.OAuth2.token_cache
    httpx_auth.OAuth2.token_cache.clear()


class Tab(threading.Thread):
    def __init__(self, reply_url: str, data: str):
        self.reply_url = reply_url
        self.data = data.encode() if data is not None else None
        self.checked = False
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
            "&httpx_auth_redirect=1"
            if "?" in reply_url
            else "?httpx_auth_redirect=1"
        )
        return urllib.request.urlopen(reply_url, data=self.data).read()

    def assert_success(self, expected_message: str, timeout: int = 1):
        self.join()
        assert (
            self.content
            == f"<body onload=\"window.open('', '_self', ''); window.setTimeout(close, {timeout})\" style=\"\n        color: #4F8A10;\n        background-color: #DFF2BF;\n        font-size: xx-large;\n        display: flex;\n        align-items: center;\n        justify-content: center;\">\n            <div style=\"border: 1px solid;\">{expected_message}</div>\n        </body>"
        )
        self.checked = True

    def assert_failure(self, expected_message: str, timeout: int = 5000):
        self.join()
        assert (
            self.content
            == f"<body onload=\"window.open('', '_self', ''); window.setTimeout(close, {timeout})\" style=\"\n        color: #D8000C;\n        background-color: #FFBABA;\n        font-size: xx-large;\n        display: flex;\n        align-items: center;\n        justify-content: center;\">\n            <div style=\"border: 1px solid;\">{expected_message}</div>\n        </body>"
        )
        self.checked = True


class BrowserMock:
    def __init__(self):
        self.tabs: Dict[str, Tab] = {}

    def open(self, url: str, new: int):
        assert new == 1
        assert url in self.tabs, f"Browser call on {url} was not mocked."
        # Simulate a browser by sending the response in another thread
        self.tabs[url].start()
        return True

    def add_response(
        self, opened_url: str, reply_url: Optional[str], data: str = None
    ) -> Tab:
        """
        :param opened_url: URL opened by httpx_auth
        :param reply_url: The URL to send a response to, None to simulate the fact that there is no redirect.
        :param data: Body of the POST response to be sent. None to send a GET request.
        """
        tab = Tab(reply_url, data)
        self.tabs[opened_url] = tab
        return tab

    def assert_checked(self):
        for url, tab in self.tabs.items():
            tab.join()
            assert tab.checked, f"Response received on {url} was not checked properly."


@pytest.fixture
def browser_mock(monkeypatch) -> BrowserMock:
    mock = BrowserMock()
    import httpx_auth.oauth2_authentication_responses_server

    monkeypatch.setattr(
        httpx_auth.oauth2_authentication_responses_server.webbrowser,
        "get",
        lambda *args: mock,
    )
    yield mock
    mock.assert_checked()


@pytest.fixture
def token_mock() -> str:
    return create_token(None)


@pytest.fixture
def token_cache_mock(monkeypatch, token_mock: str):
    class TokenCacheMock:
        def get_token(self, *args, **kwargs) -> str:
            return token_mock

    monkeypatch.setattr(httpx_auth.OAuth2, "token_cache", TokenCacheMock())
