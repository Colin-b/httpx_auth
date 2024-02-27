import uuid
from hashlib import sha512

import httpx

from httpx_auth._authentication import SupportMultiAuth
from httpx_auth._oauth2 import authentication_responses_server
from httpx_auth._oauth2.browser import BrowserAuth
from httpx_auth._oauth2.common import (
    OAuth2BaseAuth,
    _add_parameters,
    _pop_parameter,
    _get_query_parameter,
)


class OAuth2Implicit(OAuth2BaseAuth, SupportMultiAuth, BrowserAuth):
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

        header_name = kwargs.pop("header_name", None) or "Authorization"
        header_value = kwargs.pop("header_value", None) or "Bearer {token}"

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

        early_expiry = float(kwargs.pop("early_expiry", None) or 30.0)

        authorization_url_without_nonce = _add_parameters(
            self.authorization_url, kwargs
        )
        authorization_url_without_nonce, nonce = _pop_parameter(
            authorization_url_without_nonce, "nonce"
        )
        state = sha512(
            authorization_url_without_nonce.encode("unicode_escape")
        ).hexdigest()
        custom_parameters = {"state": state, "redirect_uri": self.redirect_uri}
        if nonce:
            custom_parameters["nonce"] = nonce
        grant_url = _add_parameters(authorization_url_without_nonce, custom_parameters)
        self.grant_details = authentication_responses_server.GrantDetails(
            grant_url,
            token_field_name,
            self.timeout,
            self.redirect_uri_port,
        )

        OAuth2BaseAuth.__init__(
            self,
            state,
            early_expiry,
            header_name,
            header_value,
        )

    def request_new_token(self) -> tuple[str, str]:
        return authentication_responses_server.request_new_grant(self.grant_details)


class AzureActiveDirectoryImplicit(OAuth2Implicit):
    """
    Describes an Azure Active Directory (OAuth 2) "Access Token" requests authentication.
    https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens
    """

    def __init__(self, tenant_id: str, client_id: str, **kwargs):
        """
        :param tenant_id: Microsoft Tenant Identifier (formatted as a Universal Unique Identifier)
        :param client_id: Microsoft Application Identifier (formatted as a Universal Unique Identifier)
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
        :param tenant_id: Microsoft Tenant Identifier (formatted as a Universal Unique Identifier)
        :param client_id: Microsoft Application Identifier (formatted as a Universal Unique Identifier)
        :param response_type: Value of the response_type query parameter.
        id_token by default.
        :param token_field_name: Name of the expected field containing the token.
        id_token by default.
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
        :param authorization_server: Okta authorization server.
        default by default.
        :param scope: Scope parameter sent in query. Can also be a list of scopes.
        Request ['openid', 'profile', 'email'] by default.
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
        :param client_id: Okta Application Identifier (formatted as a Universal Unique Identifier)
        :param response_type: Value of the response_type query parameter.
        id_token by default.
        :param token_field_name: Name of the expected field containing the token.
        id_token by default.
        :param early_expiry: Number of seconds before actual token expiry where token will be considered as expired.
        Default to 30 seconds to ensure token will not expire between the time of retrieval and the time the request
        reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry.
        :param nonce: Refer to http://openid.net/specs/openid-connect-core-1_0.html#IDToken for more details
        (formatted as a Universal Unique Identifier - UUID). Use a newly generated UUID by default.
        :param authorization_server: Okta authorization server
        default by default.
        :param scope: Scope parameter sent in query. Can also be a list of scopes.
        Request ['openid', 'profile', 'email'] by default.
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
