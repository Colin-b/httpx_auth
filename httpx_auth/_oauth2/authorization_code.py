from hashlib import sha512
from typing import Iterable, Union

import httpx

from httpx_auth._authentication import SupportMultiAuth
from httpx_auth._oauth2 import authentication_responses_server
from httpx_auth._oauth2.browser import BrowserAuth
from httpx_auth._oauth2.common import (
    request_new_grant_with_post,
    OAuth2BaseAuth,
    _add_parameters,
    _pop_parameter,
    _get_query_parameter,
)


class OAuth2AuthorizationCode(OAuth2BaseAuth, SupportMultiAuth, BrowserAuth):
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
        :param redirect_uri_domain: FQDN to use in the redirect_uri when localhost (default) is not allowed.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 code will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a code or a token to be received once requested.
        Wait for 1 minute by default.
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
        :param username: Username in case basic authentication should be used to retrieve token.
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

        header_name = kwargs.pop("header_name", None) or "Authorization"
        header_value = kwargs.pop("header_value", None) or "Bearer {token}"

        self.token_field_name = kwargs.pop("token_field_name", None) or "access_token"
        early_expiry = float(kwargs.pop("early_expiry", None) or 30.0)

        username = kwargs.pop("username", None)
        password = kwargs.pop("password", None)
        self.auth = (username, password) if username and password else None
        self.client = kwargs.pop("client", None)

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
        state = sha512(
            authorization_url_without_nonce.encode("unicode_escape")
        ).hexdigest()
        custom_code_parameters = {
            "state": state,
            "redirect_uri": self.redirect_uri,
        }
        if nonce:
            custom_code_parameters["nonce"] = nonce
        code_grant_url = _add_parameters(
            authorization_url_without_nonce, custom_code_parameters
        )
        self.code_grant_details = authentication_responses_server.GrantDetails(
            code_grant_url,
            code_field_name,
            self.timeout,
            self.redirect_uri_port,
        )

        # As described in https://tools.ietf.org/html/rfc6749#section-4.1.3
        self.token_data = {
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }
        self.token_data.update(kwargs)

        # As described in https://tools.ietf.org/html/rfc6749#section-6
        self.refresh_data = {"grant_type": "refresh_token"}
        self.refresh_data.update(kwargs)

        OAuth2BaseAuth.__init__(
            self,
            state,
            early_expiry,
            header_name,
            header_value,
            self.refresh_token,
        )

    def request_new_token(self) -> tuple:
        # Request code
        state, code = authentication_responses_server.request_new_grant(
            self.code_grant_details
        )

        # As described in https://tools.ietf.org/html/rfc6749#section-4.1.3
        self.token_data["code"] = code

        client = self.client or httpx.Client()
        self._configure_client(client)
        try:
            # As described in https://tools.ietf.org/html/rfc6749#section-4.1.4
            token, expires_in, refresh_token = request_new_grant_with_post(
                self.token_url, self.token_data, self.token_field_name, client
            )
        finally:
            # Close client only if it was created by this module
            if self.client is None:
                client.close()
        # Handle both Access and Bearer tokens
        return (
            (self.state, token, expires_in, refresh_token)
            if expires_in
            else (self.state, token)
        )

    def refresh_token(self, refresh_token: str) -> tuple:
        client = self.client or httpx.Client()
        self._configure_client(client)
        try:
            # As described in https://tools.ietf.org/html/rfc6749#section-6
            self.refresh_data["refresh_token"] = refresh_token
            token, expires_in, refresh_token = request_new_grant_with_post(
                self.token_url,
                self.refresh_data,
                self.token_field_name,
                client,
            )
        finally:
            # Close client only if it was created by this module
            if self.client is None:
                client.close()
        return self.state, token, expires_in, refresh_token

    def _configure_client(self, client: httpx.Client):
        client.auth = self.auth
        client.timeout = self.timeout


class OktaAuthorizationCode(OAuth2AuthorizationCode):
    """
    Describes an Okta (OAuth 2) "Access Token" authorization code flow requests authentication.
    """

    def __init__(self, instance: str, client_id: str, **kwargs):
        """
        :param instance: Okta instance (like "testserver.okta-emea.com")
        :param client_id: Okta Application Identifier (formatted as a Universal Unique Identifier)
        :param response_type: Value of the response_type query parameter.
        token by default.
        :param token_field_name: Name of the expected field containing the token.
        access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as a Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param authorization_server: Okta authorization server
        default by default.
        :param scope: Scope parameter sent in query. Can also be a list of scopes.
        Request 'openid' by default.
        :param redirect_uri_domain: FQDN to use in the redirect_uri when localhost (default) is not allowed.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
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


class WakaTimeAuthorizationCode(OAuth2AuthorizationCode):
    """
    Describes a WakaTime (OAuth 2) "Access Token" authorization code flow requests authentication.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        scope: Union[str, Iterable[str]],
        **kwargs,
    ):
        """
        :param client_id: WakaTime Application Identifier (formatted as a Universal Unique Identifier)
        :param client_secret: WakaTime Application Secret (formatted as waka_sec_ followed by a Universal Unique Identifier)
        :param scope: Scope parameter sent in query. Can also be a list of scopes.
        :param response_type: Value of the response_type query parameter.
        token by default.
        :param token_field_name: Name of the expected field containing the token.
        access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as a Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param redirect_uri_domain: FQDN to use in the redirect_uri when localhost (default) is not allowed.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 token will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param client: httpx.Client instance that will be used to request the token.
        Use it to provide a custom proxying rule for instance.
        :param kwargs: all additional authorization parameters that should be put as query parameter
        in the authorization URL.
        """
        if not scope:
            raise Exception("Scope is mandatory.")
        OAuth2AuthorizationCode.__init__(
            self,
            "https://wakatime.com/oauth/authorize",
            "https://wakatime.com/oauth/token",
            client_id=client_id,
            client_secret=client_secret,
            scope=",".join(scope) if isinstance(scope, list) else scope,
            **kwargs,
        )
