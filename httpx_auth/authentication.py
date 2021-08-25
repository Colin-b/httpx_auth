import base64
import os
import uuid
from hashlib import sha256, sha512
from typing import Optional, Generator, List
from urllib.parse import parse_qs, urlsplit, urlunsplit, urlencode

import httpx

try:
    import spnego

    WINDOWS_AUTH = True
except ImportError:
    spnego = None
    WINDOWS_AUTH = False

from httpx_auth import oauth2_authentication_responses_server, oauth2_tokens
from httpx_auth.errors import InvalidGrantRequest, GrantNotProvided


def _add_parameters(initial_url: str, extra_parameters: dict) -> str:
    """
    Add parameters to an URL and return the new URL.

    :param initial_url:
    :param extra_parameters: dictionary of parameters name and value.
    :return: the new URL containing parameters.
    """
    scheme, netloc, path, query_string, fragment = urlsplit(initial_url)
    query_params = parse_qs(query_string)
    query_params.update(
        {
            parameter_name: [parameter_value]
            for parameter_name, parameter_value in extra_parameters.items()
        }
    )

    new_query_string = urlencode(query_params, doseq=True)

    return urlunsplit((scheme, netloc, path, new_query_string, fragment))


def _pop_parameter(url: str, query_parameter_name: str) -> (str, Optional[str]):
    """
    Remove and return parameter of an URL.

    :param url: The URL containing (or not) the parameter.
    :param query_parameter_name: The query parameter to pop.
    :return: The new URL (without this parameter) and the parameter value (None if not found).
    """
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_params = parse_qs(query_string)
    parameter_value = query_params.pop(query_parameter_name, None)
    new_query_string = urlencode(query_params, doseq=True)

    return (
        urlunsplit((scheme, netloc, path, new_query_string, fragment)),
        parameter_value,
    )


def _get_query_parameter(url: str, param_name: str) -> Optional[str]:
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_params = parse_qs(query_string)
    all_values = query_params.get(param_name)
    return all_values[0] if all_values else None


def request_new_grant_with_post(
    url: str, data, grant_name: str, client: httpx.Client
) -> (str, int):
    with client:
        response = client.post(url, data=data)

        if response.is_error:
            # As described in https://tools.ietf.org/html/rfc6749#section-5.2
            raise InvalidGrantRequest(response)

        content = response.json()

    token = content.get(grant_name)
    if not token:
        raise GrantNotProvided(grant_name, content)
    return token, content.get("expires_in")


class OAuth2:
    token_cache = oauth2_tokens.TokenMemoryCache()


class SupportMultiAuth:
    """Inherit from this class to be able to use your class with httpx_auth provided authentication classes."""

    def __add__(self, other):
        if isinstance(other, _MultiAuth):
            return _MultiAuth(self, *other.authentication_modes)
        return _MultiAuth(self, other)

    def __and__(self, other):
        if isinstance(other, _MultiAuth):
            return _MultiAuth(self, *other.authentication_modes)
        return _MultiAuth(self, other)


class BrowserAuth:
    def __init__(self, kwargs):
        """
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 code will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a code or a token to be received once requested.
        Wait for 1 minute (60 seconds) by default.
        :param success_display_time: In case a code is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received code is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        """
        redirect_uri_endpoint = kwargs.pop("redirect_uri_endpoint", None) or ""
        self.redirect_uri_port = int(kwargs.pop("redirect_uri_port", None) or 5000)
        self.redirect_uri = (
            f"http://localhost:{self.redirect_uri_port}/{redirect_uri_endpoint}"
        )

        # Time is expressed in seconds
        self.timeout = float(kwargs.pop("timeout", None) or 60)
        # Time is expressed in milliseconds
        self.success_display_time = int(kwargs.pop("success_display_time", None) or 1)
        # Time is expressed in milliseconds
        self.failure_display_time = int(
            kwargs.pop("failure_display_time", None) or 5000
        )


class OAuth2ResourceOwnerPasswordCredentials(httpx.Auth, SupportMultiAuth):
    """
    Resource Owner Password Credentials Grant

    Describes an OAuth 2 resource owner password credentials (also called password) flow requests authentication.
    More details can be found in https://tools.ietf.org/html/rfc6749#section-4.3
    """

    def __init__(self, token_url: str, username: str, password: str, **kwargs):
        """
        :param token_url: OAuth 2 token URL.
        :param username: Resource owner user name.
        :param password: Resource owner password.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param scope: Scope parameter sent to token URL as body. Can also be a list of scopes. Not sent by default.
        :param token_field_name: Field name containing the token. access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param client: httpx.Client instance that will be used to request the token.
        Use it to provide a custom proxying rule for instance.
        :param kwargs: all additional authorization parameters that should be put as body parameters in the token URL.
        """
        self.token_url = token_url
        if not self.token_url:
            raise Exception("Token URL is mandatory.")
        self.username = username
        if not self.username:
            raise Exception("User name is mandatory.")
        self.password = password
        if not self.password:
            raise Exception("Password is mandatory.")

        self.header_name = kwargs.pop("header_name", None) or "Authorization"
        self.header_value = kwargs.pop("header_value", None) or "Bearer {token}"
        if "{token}" not in self.header_value:
            raise Exception("header_value parameter must contains {token}.")

        self.token_field_name = kwargs.pop("token_field_name", None) or "access_token"
        self.early_expiry = float(kwargs.pop("early_expiry", None) or 30.0)

        # Time is expressed in seconds
        self.timeout = int(kwargs.pop("timeout", None) or 60)
        self.client = kwargs.pop("client", None) or httpx.Client()
        self.client.auth = (self.username, self.password)
        self.client.timeout = self.timeout

        # As described in https://tools.ietf.org/html/rfc6749#section-4.3.2
        self.data = {
            "grant_type": "password",
            "username": self.username,
            "password": self.password,
        }
        scope = kwargs.pop("scope", None)
        if scope:
            self.data["scope"] = " ".join(scope) if isinstance(scope, list) else scope
        self.data.update(kwargs)

        all_parameters_in_url = _add_parameters(self.token_url, self.data)
        self.state = sha512(all_parameters_in_url.encode("unicode_escape")).hexdigest()

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        token = OAuth2.token_cache.get_token(
            self.state,
            early_expiry=self.early_expiry,
            on_missing_token=self.request_new_token,
        )
        request.headers[self.header_name] = self.header_value.format(token=token)
        yield request

    def request_new_token(self) -> tuple:
        # As described in https://tools.ietf.org/html/rfc6749#section-4.3.3
        token, expires_in = request_new_grant_with_post(
            self.token_url, self.data, self.token_field_name, self.client
        )
        # Handle both Access and Bearer tokens
        return (self.state, token, expires_in) if expires_in else (self.state, token)


class OAuth2ClientCredentials(httpx.Auth, SupportMultiAuth):
    """
    Client Credentials Grant

    Describes an OAuth 2 client credentials (also called application) flow requests authentication.
    More details can be found in https://tools.ietf.org/html/rfc6749#section-4.4
    """

    def __init__(self, token_url: str, client_id: str, client_secret: str, **kwargs):
        """
        :param token_url: OAuth 2 token URL.
        :param client_id: Resource owner user name.
        :param client_secret: Resource owner password.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param scope: Scope parameter sent to token URL as body. Can also be a list of scopes. Not sent by default.
        :param token_field_name: Field name containing the token. access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param client: httpx.Client instance that will be used to request the token.
        Use it to provide a custom proxying rule for instance.
        :param kwargs: all additional authorization parameters that should be put as query parameter in the token URL.
        """
        self.token_url = token_url
        if not self.token_url:
            raise Exception("Token URL is mandatory.")
        self.client_id = client_id
        if not self.client_id:
            raise Exception("client_id is mandatory.")
        self.client_secret = client_secret
        if not self.client_secret:
            raise Exception("client_secret is mandatory.")

        self.header_name = kwargs.pop("header_name", None) or "Authorization"
        self.header_value = kwargs.pop("header_value", None) or "Bearer {token}"
        if "{token}" not in self.header_value:
            raise Exception("header_value parameter must contains {token}.")

        self.token_field_name = kwargs.pop("token_field_name", None) or "access_token"
        self.early_expiry = float(kwargs.pop("early_expiry", None) or 30.0)

        # Time is expressed in seconds
        self.timeout = int(kwargs.pop("timeout", None) or 60)

        self.client = kwargs.pop("client", None) or httpx.Client()
        self.client.auth = (self.client_id, self.client_secret)
        self.client.timeout = self.timeout

        # As described in https://tools.ietf.org/html/rfc6749#section-4.4.2
        self.data = {"grant_type": "client_credentials"}
        scope = kwargs.pop("scope", None)
        if scope:
            self.data["scope"] = " ".join(scope) if isinstance(scope, list) else scope
        self.data.update(kwargs)

        all_parameters_in_url = _add_parameters(self.token_url, self.data)
        self.state = sha512(all_parameters_in_url.encode("unicode_escape")).hexdigest()

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        token = OAuth2.token_cache.get_token(
            self.state,
            early_expiry=self.early_expiry,
            on_missing_token=self.request_new_token,
        )
        request.headers[self.header_name] = self.header_value.format(token=token)
        yield request

    def request_new_token(self) -> tuple:
        # As described in https://tools.ietf.org/html/rfc6749#section-4.4.3
        token, expires_in = request_new_grant_with_post(
            self.token_url, self.data, self.token_field_name, self.client
        )
        # Handle both Access and Bearer tokens
        return (self.state, token, expires_in) if expires_in else (self.state, token)


class OAuth2AuthorizationCode(httpx.Auth, SupportMultiAuth, BrowserAuth):
    """
    Authorization Code Grant

    Describes an OAuth 2 authorization code (also called access code) flow requests authentication.

    Request a code with client browser, then request a token using this code.
    Store the token and use it for subsequent valid requests.

    More details can be found in https://tools.ietf.org/html/rfc6749#section-4.1
    """

    def __init__(self, authorization_url: str, token_url: str, **kwargs):
        """
        :param authorization_url: OAuth 2 authorization URL.
        :param token_url: OAuth 2 token URL.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 code will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a code or a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a code is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received code is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param response_type: Value of the response_type query parameter if not already provided in authorization URL.
        code by default.
        :param token_field_name: Field name containing the token. access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param code_field_name: Field name containing the code. code by default.
        :param username: User name in case basic authentication should be used to retrieve token.
        :param password: User password in case basic authentication should be used to retrieve token.
        :param client: httpx.Client instance that will be used to request the token.
        Use it to provide a custom proxying rule for instance.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL and as body parameters in the token URL.
        Usual parameters are:
        * client_id: Corresponding to your Application ID (in Microsoft Azure app portal)
        * client_secret: If client is not authenticated with the authorization server
        * nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        """
        self.authorization_url = authorization_url
        if not self.authorization_url:
            raise Exception("Authorization URL is mandatory.")

        self.token_url = token_url
        if not self.token_url:
            raise Exception("Token URL is mandatory.")

        BrowserAuth.__init__(self, kwargs)

        self.header_name = kwargs.pop("header_name", None) or "Authorization"
        self.header_value = kwargs.pop("header_value", None) or "Bearer {token}"
        if "{token}" not in self.header_value:
            raise Exception("header_value parameter must contains {token}.")

        self.token_field_name = kwargs.pop("token_field_name", None) or "access_token"
        self.early_expiry = float(kwargs.pop("early_expiry", None) or 30.0)

        username = kwargs.pop("username", None)
        password = kwargs.pop("password", None)
        self.auth = (username, password) if username and password else None
        self.client = kwargs.pop("client", None) or httpx.Client()
        self.client.auth = self.auth
        self.client.timeout = self.timeout

        # As described in https://tools.ietf.org/html/rfc6749#section-4.1.2
        code_field_name = kwargs.pop("code_field_name", "code")
        if _get_query_parameter(self.authorization_url, "response_type"):
            # Ensure provided value will not be overridden
            kwargs.pop("response_type", None)
        else:
            # As described in https://tools.ietf.org/html/rfc6749#section-4.1.1
            kwargs.setdefault("response_type", "code")

        authorization_url_without_nonce = _add_parameters(
            self.authorization_url, kwargs
        )
        authorization_url_without_nonce, nonce = _pop_parameter(
            authorization_url_without_nonce, "nonce"
        )
        self.state = sha512(
            authorization_url_without_nonce.encode("unicode_escape")
        ).hexdigest()
        custom_code_parameters = {
            "state": self.state,
            "redirect_uri": self.redirect_uri,
        }
        if nonce:
            custom_code_parameters["nonce"] = nonce
        code_grant_url = _add_parameters(
            authorization_url_without_nonce, custom_code_parameters
        )
        self.code_grant_details = oauth2_authentication_responses_server.GrantDetails(
            code_grant_url,
            code_field_name,
            self.timeout,
            self.success_display_time,
            self.failure_display_time,
            self.redirect_uri_port,
        )

        # As described in https://tools.ietf.org/html/rfc6749#section-4.1.3
        self.token_data = {
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }
        self.token_data.update(kwargs)

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        token = OAuth2.token_cache.get_token(
            self.state,
            early_expiry=self.early_expiry,
            on_missing_token=self.request_new_token,
        )
        request.headers[self.header_name] = self.header_value.format(token=token)
        yield request

    def request_new_token(self) -> tuple:
        # Request code
        state, code = oauth2_authentication_responses_server.request_new_grant(
            self.code_grant_details
        )

        # As described in https://tools.ietf.org/html/rfc6749#section-4.1.3
        self.token_data["code"] = code
        # As described in https://tools.ietf.org/html/rfc6749#section-4.1.4
        token, expires_in = request_new_grant_with_post(
            self.token_url, self.token_data, self.token_field_name, self.client
        )
        # Handle both Access and Bearer tokens
        return (self.state, token, expires_in) if expires_in else (self.state, token)


class OAuth2AuthorizationCodePKCE(httpx.Auth, SupportMultiAuth, BrowserAuth):
    """
    Proof Key for Code Exchange

    Describes an OAuth 2 Proof Key for Code Exchange (PKCE) flow requests authentication.

    Request a code with client browser, then request a token using this code.
    Store the token and use it for subsequent valid requests.

    More details can be found in https://tools.ietf.org/html/rfc7636
    """

    def __init__(self, authorization_url: str, token_url: str, **kwargs):
        """
        :param authorization_url: OAuth 2 authorization URL.
        :param token_url: OAuth 2 token URL.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 code will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a code or a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a code is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received code is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param response_type: Value of the response_type query parameter if not already provided in authorization URL.
        code by default.
        :param token_field_name: Field name containing the token. access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param code_field_name: Field name containing the code. code by default.
        :param client: httpx.Client instance that will be used to request the token.
        Use it to provide a custom proxying rule for instance.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL and as body parameters in the token URL.
        Usual parameters are:
        * client_id: Corresponding to your Application ID (in Microsoft Azure app portal)
        * client_secret: If client is not authenticated with the authorization server
        * nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        """
        self.authorization_url = authorization_url
        if not self.authorization_url:
            raise Exception("Authorization URL is mandatory.")

        self.token_url = token_url
        if not self.token_url:
            raise Exception("Token URL is mandatory.")

        BrowserAuth.__init__(self, kwargs)

        self.client = kwargs.pop("client", None) or httpx.Client()
        self.client.timeout = self.timeout

        self.header_name = kwargs.pop("header_name", None) or "Authorization"
        self.header_value = kwargs.pop("header_value", None) or "Bearer {token}"
        if "{token}" not in self.header_value:
            raise Exception("header_value parameter must contains {token}.")

        self.token_field_name = kwargs.pop("token_field_name", None) or "access_token"
        self.early_expiry = float(kwargs.pop("early_expiry", None) or 30.0)

        # As described in https://tools.ietf.org/html/rfc6749#section-4.1.2
        code_field_name = kwargs.pop("code_field_name", "code")
        authorization_url_without_response_type, response_type = _pop_parameter(
            self.authorization_url, "response_type"
        )
        if response_type:
            # Ensure provided value will not be overridden
            kwargs["response_type"] = response_type
        else:
            # As described in https://tools.ietf.org/html/rfc6749#section-4.1.1
            kwargs.setdefault("response_type", "code")

        authorization_url_without_nonce = _add_parameters(
            authorization_url_without_response_type, kwargs
        )
        authorization_url_without_nonce, nonce = _pop_parameter(
            authorization_url_without_nonce, "nonce"
        )
        self.state = sha512(
            authorization_url_without_nonce.encode("unicode_escape")
        ).hexdigest()
        custom_code_parameters = {
            "state": self.state,
            "redirect_uri": self.redirect_uri,
        }
        if nonce:
            custom_code_parameters["nonce"] = nonce

        # generate PKCE code verifier and challenge
        code_verifier = self.generate_code_verifier()
        code_challenge = self.generate_code_challenge(code_verifier)

        # add code challenge parameters to the authorization_url request
        custom_code_parameters["code_challenge"] = code_challenge
        custom_code_parameters["code_challenge_method"] = "S256"

        code_grant_url = _add_parameters(
            authorization_url_without_nonce, custom_code_parameters
        )
        self.code_grant_details = oauth2_authentication_responses_server.GrantDetails(
            code_grant_url,
            code_field_name,
            self.timeout,
            self.success_display_time,
            self.failure_display_time,
            self.redirect_uri_port,
        )

        # As described in https://tools.ietf.org/html/rfc6749#section-4.1.3
        # include the PKCE code verifier used in the second part of the flow
        self.token_data = {
            "code_verifier": code_verifier.decode("ascii"),
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }
        self.token_data.update(kwargs)

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        token = OAuth2.token_cache.get_token(
            self.state,
            early_expiry=self.early_expiry,
            on_missing_token=self.request_new_token,
        )
        request.headers[self.header_name] = self.header_value.format(token=token)
        yield request

    def request_new_token(self) -> tuple:
        # Request code
        state, code = oauth2_authentication_responses_server.request_new_grant(
            self.code_grant_details
        )

        # As described in https://tools.ietf.org/html/rfc6749#section-4.1.3
        self.token_data["code"] = code
        # As described in https://tools.ietf.org/html/rfc6749#section-4.1.4
        token, expires_in = request_new_grant_with_post(
            self.token_url, self.token_data, self.token_field_name, self.client
        )
        # Handle both Access and Bearer tokens
        return (self.state, token, expires_in) if expires_in else (self.state, token)

    @staticmethod
    def generate_code_verifier() -> bytes:
        """
        Source: https://github.com/openstack/deb-python-oauth2client/blob/master/oauth2client/_pkce.py

        Generates a 'code_verifier' as described in section 4.1 of RFC 7636.
        This is a 'high-entropy cryptographic random string' that will be
        impractical for an attacker to guess.

        https://tools.ietf.org/html/rfc7636#section-4.1

        :return: urlsafe base64-encoded random data.
        """
        return base64.urlsafe_b64encode(os.urandom(64)).rstrip(b"=")

    @staticmethod
    def generate_code_challenge(verifier: bytes) -> bytes:
        """
        Source: https://github.com/openstack/deb-python-oauth2client/blob/master/oauth2client/_pkce.py

        Creates a 'code_challenge' as described in section 4.2 of RFC 7636
        by taking the sha256 hash of the verifier and then urlsafe
        base64-encoding it.

        https://tools.ietf.org/html/rfc7636#section-4.1

        :param verifier: code_verifier as generated by generate_code_verifier()
        :return: urlsafe base64-encoded sha256 hash digest, without '=' padding.
        """
        digest = sha256(verifier).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=")


class OAuth2Implicit(httpx.Auth, SupportMultiAuth, BrowserAuth):
    """
    Implicit Grant

    Describes an OAuth 2 implicit flow requests authentication.

    Request a token with client browser.
    Store the token and use it for subsequent valid requests.

    More details can be found in https://tools.ietf.org/html/rfc6749#section-4.2
    """

    def __init__(self, authorization_url: str, **kwargs):
        """
        :param authorization_url: OAuth 2 authorization URL.
        :param response_type: Value of the response_type query parameter if not already provided in authorization URL.
        token by default.
        :param token_field_name: Name of the expected field containing the token.
        id_token by default if response_type is id_token, else access_token.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        Usual parameters are:
        * client_id: Corresponding to your Application ID (in Microsoft Azure app portal)
        * nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        * prompt: none to avoid prompting the user if a session is already opened.
        """
        self.authorization_url = authorization_url
        if not self.authorization_url:
            raise Exception("Authorization URL is mandatory.")

        BrowserAuth.__init__(self, kwargs)

        self.header_name = kwargs.pop("header_name", None) or "Authorization"
        self.header_value = kwargs.pop("header_value", None) or "Bearer {token}"
        if "{token}" not in self.header_value:
            raise Exception("header_value parameter must contains {token}.")

        response_type = _get_query_parameter(self.authorization_url, "response_type")
        if response_type:
            # Ensure provided value will not be overridden
            kwargs.pop("response_type", None)
        else:
            # As described in https://tools.ietf.org/html/rfc6749#section-4.2.1
            response_type = kwargs.setdefault("response_type", "token")

        # As described in https://tools.ietf.org/html/rfc6749#section-4.2.2
        token_field_name = kwargs.pop("token_field_name", None)
        if not token_field_name:
            token_field_name = (
                "id_token" if "id_token" == response_type else "access_token"
            )

        self.early_expiry = float(kwargs.pop("early_expiry", None) or 30.0)

        authorization_url_without_nonce = _add_parameters(
            self.authorization_url, kwargs
        )
        authorization_url_without_nonce, nonce = _pop_parameter(
            authorization_url_without_nonce, "nonce"
        )
        self.state = sha512(
            authorization_url_without_nonce.encode("unicode_escape")
        ).hexdigest()
        custom_parameters = {"state": self.state, "redirect_uri": self.redirect_uri}
        if nonce:
            custom_parameters["nonce"] = nonce
        grant_url = _add_parameters(authorization_url_without_nonce, custom_parameters)
        self.grant_details = oauth2_authentication_responses_server.GrantDetails(
            grant_url,
            token_field_name,
            self.timeout,
            self.success_display_time,
            self.failure_display_time,
            self.redirect_uri_port,
        )

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        token = OAuth2.token_cache.get_token(
            self.state,
            early_expiry=self.early_expiry,
            on_missing_token=oauth2_authentication_responses_server.request_new_grant,
            grant_details=self.grant_details,
        )
        request.headers[self.header_name] = self.header_value.format(token=token)
        yield request


class AzureActiveDirectoryImplicit(OAuth2Implicit):
    """
    Describes an Azure Active Directory (OAuth 2) "Access Token" requests authentication.
    https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens
    """

    def __init__(self, tenant_id: str, client_id: str, **kwargs):
        """
        :param tenant_id: Microsoft Tenant Identifier (formatted as an Universal Unique Identifier)
        :param client_id: Microsoft Application Identifier (formatted as an Universal Unique Identifier)
        :param response_type: Value of the response_type query parameter.
        token by default.
        :param token_field_name: Name of the expected field containing the token.
        access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as an Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        Usual parameters are:
        * prompt: none to avoid prompting the user if a session is already opened.
        """
        OAuth2Implicit.__init__(
            self,
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/authorize",
            client_id=client_id,
            nonce=kwargs.pop("nonce", None) or str(uuid.uuid4()),
            **kwargs,
        )


class AzureActiveDirectoryImplicitIdToken(OAuth2Implicit):
    """
    Describes an Azure Active Directory (OpenID Connect) "ID Token" requests authentication.
    https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
    """

    def __init__(self, tenant_id: str, client_id: str, **kwargs):
        """
        :param tenant_id: Microsoft Tenant Identifier (formatted as an Universal Unique Identifier)
        :param client_id: Microsoft Application Identifier (formatted as an Universal Unique Identifier)
        :param response_type: Value of the response_type query parameter.
        id_token by default.
        :param token_field_name: Name of the expected field containing the token.
        id_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as an Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        Usual parameters are:
        * prompt: none to avoid prompting the user if a session is already opened.
        """
        OAuth2Implicit.__init__(
            self,
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/authorize",
            client_id=client_id,
            response_type=kwargs.pop("response_type", "id_token"),
            token_field_name=kwargs.pop("token_field_name", "id_token"),
            nonce=kwargs.pop("nonce", None) or str(uuid.uuid4()),
            **kwargs,
        )


class OktaImplicit(OAuth2Implicit):
    """
    Describes an Okta (OAuth 2) "Access Token" implicit flow requests authentication.

    https://developer.okta.com/docs/guides/implement-implicit/overview/
    """

    def __init__(self, instance: str, client_id: str, **kwargs):
        """
        :param instance: Okta instance (like "testserver.okta-emea.com")
        :param client_id: Okta Application Identifier (formatted as an Universal Unique Identifier)
        :param response_type: Value of the response_type query parameter.
        token by default.
        :param token_field_name: Name of the expected field containing the token.
        access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as an Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param authorization_server: Okta authorization server.
        default by default.
        :param scope: Scope parameter sent in query. Can also be a list of scopes.
        Request ['openid', 'profile', 'email'] by default.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        Usual parameters are:
        * prompt: none to avoid prompting the user if a session is already opened.
        """
        authorization_server = kwargs.pop("authorization_server", None) or "default"
        scopes = kwargs.pop("scope", None) or ["openid", "profile", "email"]
        kwargs["scope"] = " ".join(scopes) if isinstance(scopes, list) else scopes
        OAuth2Implicit.__init__(
            self,
            f"https://{instance}/oauth2/{authorization_server}/v1/authorize",
            client_id=client_id,
            nonce=kwargs.pop("nonce", None) or str(uuid.uuid4()),
            **kwargs,
        )


class OktaImplicitIdToken(OAuth2Implicit):
    """
    Describes an Okta (OpenID Connect) "ID Token" implicit flow requests authentication.
    """

    def __init__(self, instance: str, client_id: str, **kwargs):
        """
        :param instance: Okta instance (like "testserver.okta-emea.com")
        :param client_id: Okta Application Identifier (formatted as an Universal Unique Identifier)
        :param response_type: Value of the response_type query parameter.
        id_token by default.
        :param token_field_name: Name of the expected field containing the token.
        id_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as an Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param authorization_server: Okta authorization server
        default by default.
        :param scope: Scope parameter sent in query. Can also be a list of scopes.
        Request ['openid', 'profile', 'email'] by default.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        Usual parameters are:
        * prompt: none to avoid prompting the user if a session is already opened.
        """
        authorization_server = kwargs.pop("authorization_server", None) or "default"
        scopes = kwargs.pop("scope", None) or ["openid", "profile", "email"]
        kwargs["scope"] = " ".join(scopes) if isinstance(scopes, list) else scopes
        OAuth2Implicit.__init__(
            self,
            f"https://{instance}/oauth2/{authorization_server}/v1/authorize",
            client_id=client_id,
            response_type=kwargs.pop("response_type", "id_token"),
            token_field_name=kwargs.pop("token_field_name", "id_token"),
            nonce=kwargs.pop("nonce", None) or str(uuid.uuid4()),
            **kwargs,
        )


class OktaAuthorizationCode(OAuth2AuthorizationCode):
    """
    Describes an Okta (OAuth 2) "Access Token" authorization code flow requests authentication.
    """

    def __init__(self, instance: str, client_id: str, **kwargs):
        """
        :param instance: Okta instance (like "testserver.okta-emea.com")
        :param client_id: Okta Application Identifier (formatted as an Universal Unique Identifier)
        :param response_type: Value of the response_type query parameter.
        token by default.
        :param token_field_name: Name of the expected field containing the token.
        access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as an Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param authorization_server: Okta authorization server
        default by default.
        :param scope: Scope parameter sent in query. Can also be a list of scopes.
        Request 'openid' by default.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param client: httpx.Client instance that will be used to request the token.
        Use it to provide a custom proxying rule for instance.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        Usual parameters are:
        * prompt: none to avoid prompting the user if a session is already opened.
        """
        authorization_server = kwargs.pop("authorization_server", None) or "default"
        scopes = kwargs.pop("scope", "openid")
        kwargs["scope"] = " ".join(scopes) if isinstance(scopes, list) else scopes
        OAuth2AuthorizationCode.__init__(
            self,
            f"https://{instance}/oauth2/{authorization_server}/v1/authorize",
            f"https://{instance}/oauth2/{authorization_server}/v1/token",
            client_id=client_id,
            **kwargs,
        )


class OktaAuthorizationCodePKCE(OAuth2AuthorizationCodePKCE):
    """
    Describes an Okta (OAuth 2) "Access Token" Proof Key for Code Exchange (PKCE) flow requests authentication.
    """

    def __init__(self, instance: str, client_id: str, **kwargs):
        """
        :param instance: Okta instance (like "testserver.okta-emea.com")
        :param client_id: Okta Application Identifier (formatted as an Universal Unique Identifier)
        :param response_type: Value of the response_type query parameter.
        code by default.
        :param token_field_name: Name of the expected field containing the token.
        access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param code_field_name: Field name containing the code. code by default.
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as an Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param authorization_server: Okta authorization server
        default by default.
        :param scope: Scope parameter sent in query. Can also be a list of scopes.
        Request 'openid' by default.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param success_display_time: In case a token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param failure_display_time: In case received token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param client: httpx.Client instance that will be used to request the token.
        Use it to provide a custom proxying rule for instance.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL and as body parameters in the token URL.
        Usual parameters are:
        * client_secret: If client is not authenticated with the authorization server
        * nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        """
        authorization_server = kwargs.pop("authorization_server", None) or "default"
        scopes = kwargs.pop("scope", "openid")
        kwargs["scope"] = " ".join(scopes) if isinstance(scopes, list) else scopes
        OAuth2AuthorizationCodePKCE.__init__(
            self,
            f"https://{instance}/oauth2/{authorization_server}/v1/authorize",
            f"https://{instance}/oauth2/{authorization_server}/v1/token",
            client_id=client_id,
            **kwargs,
        )


class OktaClientCredentials(OAuth2ClientCredentials):
    """
    Describes an Okta (OAuth 2) client credentials (also called application) flow requests authentication.
    """

    def __init__(self, instance: str, client_id: str, client_secret: str, **kwargs):
        """
        :param instance: Okta instance (like "testserver.okta-emea.com")
        :param client_id: Okta Application Identifier (formatted as an Universal Unique Identifier)
        :param client_secret: Resource owner password.
        :param authorization_server: Okta authorization server
        default by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param scope: Scope parameter sent to token URL as body. Can also be a list of scopes.
        Request 'openid' by default.
        :param token_field_name: Field name containing the token. access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param client: httpx.Client instance that will be used to request the token.
        Use it to provide a custom proxying rule for instance.
        :param kwargs: all additional authorization parameters that should be put as query parameter in the token URL.
        """
        authorization_server = kwargs.pop("authorization_server", None) or "default"
        scopes = kwargs.pop("scope", "openid")
        kwargs["scope"] = " ".join(scopes) if isinstance(scopes, list) else scopes
        OAuth2ClientCredentials.__init__(
            self,
            f"https://{instance}/oauth2/{authorization_server}/v1/token",
            client_id=client_id,
            client_secret=client_secret,
            **kwargs,
        )


class HeaderApiKey(httpx.Auth, SupportMultiAuth):
    """Describes an API Key requests authentication."""

    def __init__(self, api_key: str, header_name: str = None):
        """
        :param api_key: The API key that will be sent.
        :param header_name: Name of the header field. "X-API-Key" by default.
        """
        self.api_key = api_key
        if not api_key:
            raise Exception("API Key is mandatory.")
        self.header_name = header_name or "X-API-Key"

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers[self.header_name] = self.api_key
        yield request


class QueryApiKey(httpx.Auth, SupportMultiAuth):
    """Describes an API Key requests authentication."""

    def __init__(self, api_key: str, query_parameter_name: str = None):
        """
        :param api_key: The API key that will be sent.
        :param query_parameter_name: Name of the query parameter. "api_key" by default.
        """
        self.api_key = api_key
        if not api_key:
            raise Exception("API Key is mandatory.")
        self.query_parameter_name = query_parameter_name or "api_key"

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        request.url = request.url.copy_merge_params(
            {self.query_parameter_name: self.api_key}
        )
        yield request


class Basic(httpx.BasicAuth, SupportMultiAuth):
    """Describes a basic requests authentication."""

    def __init__(self, username: str, password: str):
        httpx.BasicAuth.__init__(self, username, password)


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


class _MultiAuth(httpx.Auth):
    """Authentication using multiple authentication methods."""

    def __init__(self, *authentication_modes):
        self.authentication_modes = authentication_modes

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        for authentication_mode in self.authentication_modes:
            next(authentication_mode.auth_flow(request))
        yield request

    def __add__(self, other) -> "_MultiAuth":
        if isinstance(other, _MultiAuth):
            return _MultiAuth(*self.authentication_modes, *other.authentication_modes)
        return _MultiAuth(*self.authentication_modes, other)

    def __and__(self, other) -> "_MultiAuth":
        if isinstance(other, _MultiAuth):
            return _MultiAuth(*self.authentication_modes, *other.authentication_modes)
        return _MultiAuth(*self.authentication_modes, other)
