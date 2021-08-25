import base64
from typing import Generator, List, Optional

import httpx
from httpx_auth.authentication import SupportMultiAuth

try:
    import spnego

    WINDOWS_AUTH = True
except ImportError:
    spnego = None
    WINDOWS_AUTH = False


class Negotiate(httpx.Auth, SupportMultiAuth):
    """
    NOTE: This does not support Channel Bindings which can (and ought to be) supported by servers. This is due to a
    limitation in the HTTPCore library at present.
    """

    _username: str
    _password: str
    force_ntlm: bool
    auth_header: str
    auth_complete: bool
    auth_type: str
    _service: str
    _context_proxy: "spnego._context.ContextProxy"
    max_redirects: int = 10

    def __init__(
        self,
        username: str = None,
        password: str = None,
        force_ntlm: bool = False,
        service: str = None,
        max_redirects: int = 10,
    ) -> None:
        """
        :param username: Username and domain (if required). Optional for servers that support Kerberos, required for
        those that require NTLM
        :param password: Password if required by server for authentication.
        :param force_ntlm: Force authentication to use NTLM if available.
        :param service: Service portion of the target Service Principal Name (default HTTP)
        :return: None
        """
        if not WINDOWS_AUTH:
            raise ImportError(
                "Windows authentication support not enabled, install with the windows_auth extra."
            )
        if password and not username:
            raise ValueError(
                "Negotiate authentication with credentials requires username and password, no username was provided."
            )
        if force_ntlm and not (username and password):
            raise ValueError(
                "NTLM authentication requires credentials, provide a username and password."
            )
        self._username = username
        self._password = password
        self.force_ntlm = force_ntlm
        self.auth_header = ""
        self.auth_complete = False
        self.auth_type = ""
        self._service = service
        self.max_redirects = max_redirects

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:

        responses = []
        response = yield request
        responses.append(response)

        redirect_count = 0

        # If anything comes back except an authenticate challenge then return it for the client to deal with, hopefully
        # a successful response.
        if responses[-1].status_code != 401:
            return responses[-1]

        # Otherwise authenticate. Determine the authentication name to use, prefer Negotiate if available.
        self.auth_type = self._auth_type_from_header(
            responses[-1].headers.get("WWW-Authenticate")
        )
        if self.auth_type is None:
            return responses[-1]

        # Run authentication flow.
        yield from self._do_auth_flow(request, responses)

        # If we were redirected we will need to rerun the auth flow on the new url, repeat until either we receive a
        # status that is not 401 Unauthorized, or until the url we ended up at is the same as the one we requested.
        while responses[-1].status_code == 401 and responses[-1].url != request.url:
            redirect_count += 1
            if redirect_count > self.max_redirects:
                raise httpx.TooManyRedirects(
                    message=f"Redirected too many times ({self.max_redirects}).",
                    request=request,
                )
            request.url = responses[-1].url
            yield from self._do_auth_flow(request, responses)

        return responses[-1]

    def _do_auth_flow(
        self, request: httpx.Request, responses: List[httpx.Response]
    ) -> Generator[httpx.Request, httpx.Response, None]:
        # Phase 1:
        # Configure context proxy, generate message header, attach to request and resend.
        host = request.url.host
        self.context_proxy = self._new_context_proxy()
        self.context_proxy.spn = "{0}/{1}".format(
            self._service.upper() if self._service else "HTTP", host
        )
        request.headers["Authorization"] = self._make_authorization_header(
            self.context_proxy.step(None)
        )
        response = yield request
        responses.append(response)

        # Phase 2:
        # Server responds with Challenge message, parse the authenticate header and deal with cookies. Some web apps use
        # cookies to store progress in the auth process.
        if "set-cookie" in responses[-1].headers:
            request.headers["Cookie"] = responses[-1].headers["Cookie"]

        auth_header_bytes = self._parse_authenticate_header(
            responses[-1].headers["WWW-Authenticate"]
        )

        # Phase 3:
        # Generate Authenticate message, attach to the request and resend it. If the user is authorized then this will
        # succeed. If not then this will fail.
        self.auth_header = self._make_authorization_header(
            self.context_proxy.step(auth_header_bytes)
        )
        request.headers["Authorization"] = self.auth_header
        response = yield request
        responses.append(response)

    def _new_context_proxy(self) -> "spnego._context.ContextProxy":
        client = spnego.client(
            self._username,
            self._password,
            service=self._service,
            protocol="ntlm" if self.force_ntlm else "negotiate",
        )
        if self.force_ntlm:
            client.options = spnego.NegotiateOptions.use_ntlm
            client.protocol = "ntlm"
        return client

    def _parse_authenticate_header(self, header: str) -> bytes:
        """
        Extract NTLM/Negotiate value from Authenticate header and convert to bytes
        :param header: str WWW-Authenticate header
        :return: bytes Negotiate challenge
        """

        auth_strip = self.auth_type.lower() + " "
        auth_header_value = next(
            s
            for s in (val.lstrip() for val in header.split(","))
            if s.lower().startswith(auth_strip)
        )
        return base64.b64decode(auth_header_value[len(auth_strip) :])

    def _make_authorization_header(self, response_bytes: bytes) -> str:
        """
        Convert the auth bytes to base64 encoded string and build Authorization header.
        :param response_bytes: bytes auth response content
        :return: str Authorization/Proxy-Authorization header
        """

        auth_response = base64.b64encode(response_bytes).decode("ascii")
        return f"{self.auth_type} {auth_response}"

    @staticmethod
    def _auth_type_from_header(header: str) -> Optional[str]:
        """
        Given a WWW-Authenticate header, returns the authentication type to use.
        :param header: str Authenticate header
        :return: Optional[str] Authentication type or None if not supported
        """
        if "negotiate" in header.lower():
            return "Negotiate"
        elif "ntlm" in header.lower():
            return "NTLM"
        return None
