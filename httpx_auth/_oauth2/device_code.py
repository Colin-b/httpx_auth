import time
from hashlib import sha512

import httpx

from httpx_auth._authentication import SupportMultiAuth
from httpx_auth._oauth2.browser import BrowserAuth
from httpx_auth._oauth2.common import (
    OAuth2BaseAuth,
    _add_parameters,
    _get_query_parameter,
    _pop_parameter,
    request_device_code_with_post,
    request_new_grant_with_post,
)


class DeviceCodeDetails:
    def __init__(
        self,
        url: str,
        user_code_field: str,
        device_code_field: str,
        uri_field: int,
    ):

        self.url = url
        self.user_code_field = user_code_field
        self.device_code_field = device_code_field
        self.uri_field = uri_field


class OAuth2DeviceCode(OAuth2BaseAuth, SupportMultiAuth, BrowserAuth):
    """
    Device Code Flow

    Describes an OAuth 2 device code flow requests authentication.

    Request device & user codes & verication uri, user then uses verfication uri and user code to verify,
    then request a token using this code. Store the token and use it for subsequent valid requests.

    More details can be found in https://tools.ietf.org/html/rfc6749#section-4.1
    """

    def __init__(self, device_url: str, token_url: str, **kwargs):
        """
        :param device_url: OAuth 2 device URL.
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
        self.device_url = device_url
        if not self.device_url:
            raise Exception("Device URL is mandatory.")

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

        user_code_field_name = kwargs.pop("user_code_field_name", "user_code")
        device_code_field_name = kwargs.pop("device_code_field_name", "device_code")
        uri_field_name = kwargs.pop("uri_field_name", "verification_uri")

        if _get_query_parameter(self.device_url, "response_type"):
            # Ensure provided value will not be overridden
            kwargs.pop("response_type", None)
        else:
            kwargs.setdefault("response_type", "device_code")

        device_url_without_nonce = _add_parameters(self.device_url, kwargs)
        device_url_without_nonce, nonce = _pop_parameter(device_url_without_nonce, "nonce")
        state = sha512(device_url_without_nonce.encode("unicode_escape")).hexdigest()
        custom_code_parameters = {"state": state}

        if nonce:
            custom_code_parameters["nonce"] = nonce

        device_code_url = _add_parameters(device_url_without_nonce, custom_code_parameters)
        self.device_code_details = DeviceCodeDetails(
            device_code_url,
            user_code_field_name,
            device_code_field_name,
            uri_field_name,
        )

        self.device_data = kwargs

        self.token_data = {
            "grant_type": "device_code",
            "redirect_uri": self.redirect_uri,
        }
        self.token_data.update(kwargs)

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
        client = self.client or httpx.Client()
        self._configure_client(client)

        user_code, device_code, verification_uri, verification_uri_complete, expires_in, interval = (
            request_device_code_with_post(
                self.device_url,
                self.device_data,
                self.device_code_details.user_code_field,
                self.device_code_details.device_code_field,
                self.device_code_details.uri_field,
                client,
            )
        )

        if verification_uri_complete:
            print(f"To sign in, go to: {verification_uri_complete}")
        else:
            print(f"To sign in, go to: {verification_uri}\nEnter the following code: {user_code}")

        input("After signing in Press Enter to continue...")

        print(f"waiting for recomended interval {interval}s")
        time.sleep(interval)
        self.token_data["device_code"] = device_code

        client = self.client or httpx.Client()
        self._configure_client(client)
        try:
            token, expires_in, refresh_token = request_new_grant_with_post(
                self.token_url, self.token_data, self.token_field_name, client
            )
        finally:
            # Close client only if it was created by this module
            if self.client is None:
                client.close()
        # Handle both Access and Bearer tokens
        return (self.state, token, expires_in, refresh_token) if expires_in else (self.state, token)

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


class OktaDeviceCode(OAuth2DeviceCode):
    """
    Describes an Okta (OAuth 2) "Access Token" device code flow requests authentication.
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
        OAuth2DeviceCode.__init__(
            self,
            f"https://{instance}/oauth2/{authorization_server}/v1/authorize",
            f"https://{instance}/oauth2/{authorization_server}/v1/token",
            client_id=client_id,
            **kwargs,
        )
