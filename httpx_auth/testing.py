import urllib.request
import threading
from typing import Optional
from urllib.parse import urlsplit
import datetime

import pytest

import httpx_auth
import httpx_auth._oauth2.authentication_responses_server


def create_token(expiry: Optional[datetime.datetime]) -> str:
    import jwt  # Consider jwt an optional dependency for testing

    return jwt.encode({"exp": expiry}, "secret") if expiry else jwt.encode({}, "secret")


@pytest.fixture
def token_cache() -> httpx_auth.TokenMemoryCache:
    yield httpx_auth.OAuth2.token_cache
    httpx_auth.OAuth2.token_cache.clear()


class Tab(threading.Thread):
    """
    Simulate a Web Browser tab by sending HTTP requests the way it would.
    This allows to:
      * run tests without the need for a browser to be installed
      * run tests faster as no browser needs to be started
      * assert the content sent to the browser
    """

    def __init__(
        self,
        reply_url: str,
        data: str,
        displayed_html: Optional[str] = None,
    ):
        self.reply_url = reply_url
        self.data = data.encode() if data is not None else None
        self.checked = False
        self.success_html = (
            displayed_html
            or """<!DOCTYPE html>
<html lang="en">
    <head>
        <title>Authentication success</title>
        <style>
body {{
    border: none;
    box-sizing: border-box;
    display: block;
    font-family: "Segoe UI";
    font-weight: 500;
    line-height: 1.5;
    padding: 50px 0 76px 0;
    text-align: center;
}}

.content {{
    padding: 30px 0 50px 0;
}}

h1 {{
    color: #32cd32;
    font-size: 2.4rem;
    margin: 1.7rem auto .5rem auto;
}}

p {{
    color: #2f374f;
    font-size: 1.2rem;
    margin: .75rem 0 0 0;
}}

.btn {{
    display: inline-block;
    color: #32cd32 !important;
    text-decoration: none;
    background-color: #f0fff0;
    padding: 14px 24px;
    border-radius: 8px;
    font-size: 1em;
    font-weight: 400;
    margin: 50px 0 0 0;
}}

.btn:hover {{
    color: #f0fff0 !important;
    background-color: #32cd32;
}}

@keyframes zoomText {{
  from {{
    opacity: 0;
    transform: scale3d(0.9, 0.9, 0.9);
  }}
  50% {{
    opacity: 1;
  }}
}}

.content h1 {{
    animation-duration: .6s;
    animation-fill-mode: both;
    animation-name: zoomText;
    animation-delay: .2s;
}}
        </style>
    </head>
    <body onload="window.open('', '_self', ''); window.setTimeout(close, {display_time})">
        <div class="content">
            <h1>Authentication success</h1>
            <p>You can close this tab</p>
        </div>
        <div class="more">
            <a href="https://colin-b.github.io/httpx_auth/" class="btn" target="_blank" rel="noreferrer noopener" role="button">Documentation</a>
            <a href="https://github.com/Colin-b/httpx_auth/blob/develop/CHANGELOG.md" class="btn" target="_blank" rel="noreferrer noopener" role="button">Latest changes</a>
        </div>
    </body>
</html>"""
        )
        self.failure_html = (
            displayed_html
            or """<!DOCTYPE html>
<html lang="en">
    <head>
        <title>Authentication failed</title>
        <style>
body {{
    border: none;
    box-sizing: border-box;
    display: block;
    font-family: "Segoe UI";
    font-weight: 500;
    line-height: 1.5;
    padding: 50px 0 76px 0;
    text-align: center;
}}

.content {{
    padding: 30px 0 50px 0;
}}

h1 {{
    color: #dc143c;
    font-size: 2.4rem;
    margin: 1.7rem auto .5rem auto;
}}

p {{
    color: #2f374f;
    font-size: 1.2rem;
    margin: .75rem 0 0 0;
}}

.btn {{
    display: inline-block;
    color: #dc143c !important;
    text-decoration: none;
    background-color: #fffafa;
    padding: 14px 24px;
    border-radius: 8px;
    font-size: 1em;
    font-weight: 400;
    margin: 50px 0 0 0;
}}

.btn:hover {{
    color: #fffafa !important;
    background-color: #dc143c;
}}

@keyframes zoomText {{
  from {{
    opacity: 0;
    transform: scale3d(0.9, 0.9, 0.9);
  }}
  50% {{
    opacity: 1;
  }}
}}

.content h1 {{
    animation-duration: .6s;
    animation-fill-mode: both;
    animation-name: zoomText;
    animation-delay: .2s;
}}
        </style>
    </head>
    <body onload="window.open('', '_self', ''); window.setTimeout(close, {display_time})">
        <div class="content">
            <h1>Authentication failed</h1>
            <p>{information}</p>
        </div>
        <div class="more">
            <a href="https://colin-b.github.io/httpx_auth/" class="btn" target="_blank" rel="noreferrer noopener" role="button">Documentation</a>
            <a href="https://github.com/Colin-b/httpx_auth/blob/develop/CHANGELOG.md" class="btn" target="_blank" rel="noreferrer noopener" role="button">Latest changes</a>
        </div>
    </body>
</html>"""
        )
        super().__init__()

    def run(self) -> None:
        if not self.reply_url:
            self.checked = True
            return

        # Simulate a browser tab by first requesting a favicon
        self._request_favicon()
        # Simulate a browser tab token redirect to the reply URL
        self.content = self._simulate_redirect().decode()

    def _request_favicon(self):
        scheme, netloc, *_ = urlsplit(self.reply_url)
        favicon_response = urllib.request.urlopen(f"{scheme}://{netloc}/favicon.ico")
        assert favicon_response.read() == b"Favicon is not provided."

    def _simulate_redirect(self) -> bytes:
        content = urllib.request.urlopen(self.reply_url, data=self.data).read()
        # Simulate Javascript execution by the browser
        if (
            content
            == b'<html><body><script>\n        var new_url = window.location.href.replace("#","?");\n        if (new_url.indexOf("?") !== -1) {\n            new_url += "&httpx_auth_redirect=1";\n        } else {\n            new_url += "?httpx_auth_redirect=1";\n        }\n        window.location.replace(new_url)\n        </script></body></html>'
        ):
            content = self._simulate_httpx_auth_redirect()
        return content

    def _simulate_httpx_auth_redirect(self) -> bytes:
        # Replace fragment by query parameter as requested by Javascript
        reply_url = self.reply_url.replace("#", "?")
        # Add requests_auth_redirect query parameter as requested by Javascript
        reply_url += (
            "&httpx_auth_redirect=1" if "?" in reply_url else "?httpx_auth_redirect=1"
        )
        return urllib.request.urlopen(reply_url, data=self.data).read()

    def assert_success(self, timeout: int = 1):
        self.join()
        assert self.content == self.success_html.format(display_time=timeout)
        self.checked = True

    def assert_failure(self, expected_message: str, timeout: int = 10_000):
        self.join()
        assert self.content == self.failure_html.format(
            display_time=timeout, information=expected_message
        )
        self.checked = True


class BrowserMock:
    def __init__(self):
        self.tabs: dict[str, Tab] = {}

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
        data: Optional[str] = None,
        displayed_html: Optional[str] = None,
    ) -> Tab:
        """
        :param opened_url: URL opened by httpx_auth
        :param reply_url: The URL to send a response to, None to simulate the fact that there is no redirect.
        :param data: Body of the POST response to be sent. None to send a GET request.
        :param displayed_html: Expected success/failure page.
        """
        tab = Tab(reply_url, data, displayed_html)
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
    monkeypatch.setattr(httpx_auth.OAuth2, "display", httpx_auth.DisplaySettings())

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
