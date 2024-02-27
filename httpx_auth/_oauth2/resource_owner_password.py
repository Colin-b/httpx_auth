from hashlib import sha512

import httpx
from httpx_auth._authentication import SupportMultiAuth
from httpx_auth._oauth2.common import (
    OAuth2BaseAuth,
    request_new_grant_with_post,
    _add_parameters,
)


class OAuth2ResourceOwnerPasswordCredentials(OAuth2BaseAuth, SupportMultiAuth):
    """
    Resource Owner Password Credentials Grant

    Describes an OAuth 2 resource owner password credentials (also called password) flow requests authentication.
    More details can be found in https://tools.ietf.org/html/rfc6749#section-4.3
    """

    def __init__(self, token_url: str, username: str, password: str, **kwargs):
        """
        :param token_url: OAuth 2 token URL.
        :param username: Resource owner username.
        :param password: Resource owner password.
        :param client_auth: Client authentication if the client type is confidential
        or the client was issued client credentials (or assigned other authentication requirements).
        Can be a tuple or any httpx authentication class instance.
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

        header_name = kwargs.pop("header_name", None) or "Authorization"
        header_value = kwargs.pop("header_value", None) or "Bearer {token}"

        self.token_field_name = kwargs.pop("token_field_name", None) or "access_token"
        early_expiry = float(kwargs.pop("early_expiry", None) or 30.0)

        # Time is expressed in seconds
        self.timeout = int(kwargs.pop("timeout", None) or 60)
        self.client = kwargs.pop("client", None)
        self.client_auth = kwargs.pop("client_auth", None)

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

        # As described in https://tools.ietf.org/html/rfc6749#section-6
        self.refresh_data = {"grant_type": "refresh_token"}
        if scope:
            self.refresh_data["scope"] = self.data["scope"]
        self.refresh_data.update(kwargs)

        all_parameters_in_url = _add_parameters(self.token_url, self.data)
        state = sha512(all_parameters_in_url.encode("unicode_escape")).hexdigest()

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
        try:
            # As described in https://tools.ietf.org/html/rfc6749#section-4.3.3
            token, expires_in, refresh_token = request_new_grant_with_post(
                self.token_url, self.data, self.token_field_name, client
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
        if self.client_auth:
            client.auth = self.client_auth
        client.timeout = self.timeout


class OktaResourceOwnerPasswordCredentials(OAuth2ResourceOwnerPasswordCredentials):
    """
    Describes an Okta (OAuth 2) resource owner password credentials (also called password) flow requests authentication.
    """

    def __init__(
        self,
        instance: str,
        username: str,
        password: str,
        client_id: str,
        client_secret: str,
        **kwargs,
    ):
        """
        :param instance: Okta instance (like "testserver.okta-emea.com")
        :param username: Resource owner username.
        :param password: Resource owner password.
        :param client_id: Okta Application Identifier (formatted as a Universal Unique Identifier)
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
        :param kwargs: all additional authorization parameters that should be put as body parameters in the token URL.
        """
        if not instance:
            raise Exception("Instance is mandatory.")
        if not client_id:
            raise Exception("Client ID is mandatory.")
        if not client_secret:
            raise Exception("Client secret is mandatory.")
        authorization_server = kwargs.pop("authorization_server", None) or "default"
        scopes = kwargs.pop("scope", "openid")
        kwargs["scope"] = " ".join(scopes) if isinstance(scopes, list) else scopes
        OAuth2ResourceOwnerPasswordCredentials.__init__(
            self,
            f"https://{instance}/oauth2/{authorization_server}/v1/token",
            username=username,
            password=password,
            client_auth=(client_id, client_secret),
            **kwargs,
        )
