from hashlib import sha512
from typing import Generator, Union, Iterable

import httpx
from httpx_auth._authentication import SupportMultiAuth
from httpx_auth._oauth2.common import (
    OAuth2,
    request_new_grant_with_post,
    _add_parameters,
)


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

        self.client = kwargs.pop("client", None)

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
        client = self.client or httpx.Client()
        self._configure_client(client)
        try:
            # As described in https://tools.ietf.org/html/rfc6749#section-4.4.3
            token, expires_in, _ = request_new_grant_with_post(
                self.token_url, self.data, self.token_field_name, client
            )
        finally:
            # Close client only if it was created by this module
            if self.client is None:
                client.close()
        # Handle both Access and Bearer tokens
        return (self.state, token, expires_in) if expires_in else (self.state, token)

    def _configure_client(self, client: httpx.Client):
        client.auth = (self.client_id, self.client_secret)
        client.timeout = self.timeout


class OktaClientCredentials(OAuth2ClientCredentials):
    """
    Describes an Okta (OAuth 2) client credentials (also called application) flow requests authentication.

    More details can be found in https://developer.okta.com/docs/guides/implement-grant-type/clientcreds/main/
    """

    def __init__(
        self,
        instance: str,
        client_id: str,
        client_secret: str,
        *,
        scope: Union[str, Iterable[str]],
        **kwargs,
    ):
        """
        :param instance: Okta instance (like "testserver.okta-emea.com")
        :param client_id: Okta Application Identifier (formatted as a Universal Unique Identifier)
        :param client_secret: Resource owner password.
        :param scope: Scope parameter sent to token URL as body. Can also be a list of scopes.
        :param authorization_server: Okta authorization server
        default by default.
        :param timeout: Maximum amount of seconds to wait for a token to be received once requested.
        Wait for 1 minute by default.
        :param header_name: Name of the header field used to send token.
        Token will be sent in Authorization header field by default.
        :param header_value: Format used to send the token value.
        "{token}" must be present as it will be replaced by the actual token.
        Token will be sent as "Bearer {token}" by default.
        :param token_field_name: Field name containing the token. access_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param client: httpx.Client instance that will be used to request the token.
        Use it to provide a custom proxying rule for instance.
        :param kwargs: all additional authorization parameters that should be put as query parameter in the token URL.
        """
        if not scope:
            raise Exception("scope is mandatory.")
        if not instance:
            raise Exception("Okta instance is mandatory.")
        authorization_server = kwargs.pop("authorization_server", None) or "default"
        OAuth2ClientCredentials.__init__(
            self,
            f"https://{instance}/oauth2/{authorization_server}/v1/token",
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            **kwargs,
        )
