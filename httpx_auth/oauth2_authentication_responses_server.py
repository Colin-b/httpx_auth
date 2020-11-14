import webbrowser
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from socket import socket

import httpx

from httpx_auth.errors import (
    InvalidGrantRequest,
    GrantNotProvided,
    StateNotProvided,
    TimeoutOccurred,
)

logger = logging.getLogger(__name__)


class OAuth2ResponseHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        # Do not consider a favicon request as an error
        if self.path == "/favicon.ico":
            logger.debug(
                "Favicon request received on OAuth2 authentication response server."
            )
            return self.send_html("Favicon is not provided.")

        logger.debug(f"GET received on {self.path}")
        try:
            args = self._get_params()
            if self.server.grant_details.name in args or args.pop(
                "httpx_auth_redirect", None
            ):
                self._parse_grant(args)
            else:
                logger.debug("Send anchor grant as query parameter.")
                self.send_html(self.fragment_redirect_page())
        except Exception as e:
            self.server.request_error = e
            logger.exception("Unable to properly perform authentication.")
            self.send_html(
                self.error_page(f"Unable to properly perform authentication: {e}")
            )

    def do_POST(self) -> None:
        logger.debug(f"POST received on {self.path}")
        try:
            form_dict = self._get_form()
            self._parse_grant(form_dict)
        except Exception as e:
            self.server.request_error = e
            logger.exception("Unable to properly perform authentication.")
            self.send_html(
                self.error_page(f"Unable to properly perform authentication: {e}")
            )

    def _parse_grant(self, arguments: dict) -> None:
        grants = arguments.get(self.server.grant_details.name)
        if not grants or len(grants) > 1:
            if "error" in arguments:
                raise InvalidGrantRequest(arguments)
            raise GrantNotProvided(self.server.grant_details.name, arguments)
        logger.debug(f"Received grants: {grants}")
        grant = grants[0]

        states = arguments.get("state")
        if not states or len(states) > 1:
            raise StateNotProvided(arguments)
        logger.debug(f"Received states: {states}")
        state = states[0]
        self.server.grant = state, grant
        self.send_html(
            self.success_page(
                f"You are now authenticated on {state}. You may close this tab."
            )
        )

    def _get_form(self) -> dict:
        content_length = int(self.headers.get("Content-Length", 0))
        body_str = self.rfile.read(content_length).decode("utf-8")
        return parse_qs(body_str, keep_blank_values=1)

    def _get_params(self) -> dict:
        return parse_qs(urlparse(self.path).query)

    def send_html(self, html_content: str) -> None:
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(str.encode(html_content))
        logger.debug("HTML content sent to client.")

    def success_page(self, text: str) -> str:
        return f"""<body onload="window.open('', '_self', ''); window.setTimeout(close, {self.server.grant_details.reception_success_display_time})" style="
        color: #4F8A10;
        background-color: #DFF2BF;
        font-size: xx-large;
        display: flex;
        align-items: center;
        justify-content: center;">
            <div style="border: 1px solid;">{text}</div>
        </body>"""

    def error_page(self, text: str) -> str:
        return f"""<body onload="window.open('', '_self', ''); window.setTimeout(close, {self.server.grant_details.reception_failure_display_time})" style="
        color: #D8000C;
        background-color: #FFBABA;
        font-size: xx-large;
        display: flex;
        align-items: center;
        justify-content: center;">
            <div style="border: 1px solid;">{text}</div>
        </body>"""

    def fragment_redirect_page(self) -> str:
        """Return a page with JS that calls back the server on the url
        original url: scheme://FQDN/path#fragment
        call back url: scheme://FQDN/path?fragment

        The fragment part is used in the protocol for the client to retrieve the token.
        As the fragment part is not sent to the server (to avoid normally to see the token in the logs)
        we must call again the localhost server with the fragment transformed as query string.
        """
        return """<html><body><script>
        var new_url = window.location.href.replace("#","?");
        if (new_url.indexOf("?") !== -1) {
            new_url += "&httpx_auth_redirect=1";
        } else {
            new_url += "?httpx_auth_redirect=1";
        }
        window.location.replace(new_url)
        </script></body></html>"""

    def log_message(self, format: str, *args) -> None:
        """Make sure that messages are logged even with pythonw (seems like a bug in BaseHTTPRequestHandler)."""
        logger.debug(format, *args)


class GrantDetails:
    def __init__(
        self,
        url: str,
        name: str,
        reception_timeout: float,
        reception_success_display_time: int,
        reception_failure_display_time: int,
        redirect_uri_port: int,
    ):
        self.url = url
        self.name = name
        self.reception_timeout = reception_timeout
        self.reception_success_display_time = reception_success_display_time
        self.reception_failure_display_time = reception_failure_display_time
        self.redirect_uri_port = redirect_uri_port


class FixedHttpServer(HTTPServer):
    def __init__(self, grant_details: GrantDetails):
        HTTPServer.__init__(
            self, ("", grant_details.redirect_uri_port), OAuth2ResponseHandler
        )
        self.timeout = grant_details.reception_timeout
        logger.debug(f"Timeout is set to {self.timeout} seconds.")
        self.grant_details = grant_details
        self.request_error = None
        self.grant = False

    def finish_request(self, request: socket, client_address) -> None:
        """Make sure that timeout is used by the request (seems like a bug in HTTPServer)."""
        request.settimeout(self.timeout)
        HTTPServer.finish_request(self, request, client_address)

    def ensure_no_error_occurred(self) -> bool:
        if self.request_error:
            # Raise error encountered while processing a request if any
            raise self.request_error
        return not self.grant

    def handle_timeout(self) -> None:
        raise TimeoutOccurred(self.timeout)


def request_new_grant(grant_details: GrantDetails) -> (str, str):
    """
    Ask for a new OAuth2 grant.
    :return: A tuple (state, grant)
    :raises InvalidGrantRequest: If the request was invalid.
    :raises TimeoutOccurred: If not retrieved within timeout.
    :raises GrantNotProvided: If grant is not provided in response (but no error occurred).
    :raises StateNotProvided: If state if not provided in addition to the grant.
    """
    logger.debug(f"Requesting new {grant_details.name}...")

    with FixedHttpServer(grant_details) as server:
        _open_url(grant_details.url)
        return _wait_for_grant(server)


def _open_url(url: str) -> None:
    # Default to Microsoft Internet Explorer to be able to open a new window
    # otherwise this parameter is not taken into account by most browsers
    # Opening a new window allows to focus back once authenticated (JavaScript is closing the only tab)
    try:
        browser = (
            webbrowser.get(webbrowser.iexplore)
            if hasattr(webbrowser, "iexplore")
            else webbrowser.get()
        )
        logger.debug(f"Opening browser on {url}")
        if not browser.open(url, new=1):
            logger.warning("Unable to open URL, try with a GET request.")
            httpx.get(url)
    except webbrowser.Error:
        logger.exception("Unable to open URL, try with a GET request.")
        httpx.get(url)


def _wait_for_grant(server: FixedHttpServer) -> (str, str):
    """
    :return: A tuple (state, grant)
    :raises InvalidGrantRequest: If the request was invalid.
    :raises TimeoutOccurred: If not retrieved within timeout.
    :raises GrantNotProvided: If grant is not provided in response (but no error occurred).
    :raises StateNotProvided: If state if not provided in addition to the grant.
    """
    logger.debug("Waiting for user authentication...")
    while not server.grant:
        server.handle_request()
        server.ensure_no_error_occurred()
    return server.grant
