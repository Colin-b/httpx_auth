import base64
import os
from hashlib import sha256, sha512

import httpx

from httpx_auth._authentication import SupportMultiAuth
from httpx_auth._oauth2 import authentication_responses_server
from httpx_auth._oauth2.browser import BrowserAuth
from httpx_auth._oauth2.common import (
    request_new_grant_with_post,
    OAuth2BaseAuth,
    _add_parameters,
    _pop_parameter,
)


class OAuth2AuthorizationCodePKCE(OAuth2BaseAuth, SupportMultiAuth, BrowserAuth):
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

        self.client = kwargs.pop("client", None)

        header_name = kwargs.pop("header_name", None) or "Authorization"
        header_value = kwargs.pop("header_value", None) or "Bearer {token}"

        self.token_field_name = kwargs.pop("token_field_name", None) or "access_token"
        early_expiry = float(kwargs.pop("early_expiry", None) or 30.0)

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
        state = sha512(
            authorization_url_without_nonce.encode("unicode_escape")
        ).hexdigest()
        custom_code_parameters = {
            "state": state,
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
        self.code_grant_details = authentication_responses_server.GrantDetails(
            code_grant_url,
            code_field_name,
            self.timeout,
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

        # As described in https://tools.ietf.org/html/rfc6749#section-6
        self.refresh_data = {"grant_type": "refresh_token"}
        self.refresh_data.update(kwargs)

        OAuth2BaseAuth.__init__(
            self, state, early_expiry, header_name, header_value, self.refresh_token
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
        client.timeout = self.timeout

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


class OktaAuthorizationCodePKCE(OAuth2AuthorizationCodePKCE):
    """
    Describes an Okta (OAuth 2) "Access Token" Proof Key for Code Exchange (PKCE) flow requests authentication.
    """

    def __init__(self, instance: str, client_id: str, **kwargs):
        """
        :param instance: Okta instance (like "testserver.okta-emea.com")
        :param client_id: Okta Application Identifier (formatted as a Universal Unique Identifier)
        :param response_type: Value of the response_type query parameter.
        code by default.
        :param token_field_name: Name of the expected field containing the token.
        access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param code_field_name: Field name containing the code. code by default.
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
