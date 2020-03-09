from json import JSONDecodeError
from typing import Union

import httpx


class AuthenticationFailed(Exception):
    """ User was not authenticated. """

    def __init__(self):
        Exception.__init__(self, "User was not authenticated.")


class TimeoutOccurred(Exception):
    """ No response within timeout interval. """

    def __init__(self, timeout: float):
        Exception.__init__(
            self, f"User authentication was not received within {timeout} seconds."
        )


class InvalidToken(Exception):
    """ Token is invalid. """

    def __init__(self, token_name: str):
        Exception.__init__(self, f"{token_name} is invalid.")


class GrantNotProvided(Exception):
    """ Grant was not provided. """

    def __init__(self, grant_name: str, dictionary_without_grant: dict):
        Exception.__init__(
            self, f"{grant_name} not provided within {dictionary_without_grant}."
        )


class InvalidGrantRequest(Exception):
    """
    If the request failed client authentication or is invalid, the authorization server returns an error response as described in https://tools.ietf.org/html/rfc6749#section-5.2
    """

    # https://tools.ietf.org/html/rfc6749#section-5.2
    request_errors = {
        "invalid_request": "The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed.",
        "invalid_client": 'Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).  The authorization server MAY return an HTTP 401 (Unauthorized) status code to indicate which HTTP authentication schemes are supported.  If the client attempted to authenticate via the "Authorization" request header field, the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field matching the authentication scheme used by the client.',
        "invalid_grant": "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
        "unauthorized_client": "The authenticated client is not authorized to use this authorization grant type.",
        "unsupported_grant_type": "The authorization grant type is not supported by the authorization server.",
        "invalid_scope": "The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.",
    }

    # https://tools.ietf.org/html/rfc6749#section-4.2.2.1
    # https://tools.ietf.org/html/rfc6749#section-4.1.2.1
    browser_errors = {
        "invalid_request": "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
        "unauthorized_client": "The client is not authorized to request an authorization code or an access token using this method.",
        "access_denied": "The resource owner or authorization server denied the request.",
        "unsupported_response_type": "The authorization server does not support obtaining an authorization code or an access token using this method.",
        "invalid_scope": "The requested scope is invalid, unknown, or malformed.",
        "server_error": "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)",
        "temporarily_unavailable": "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.  (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)",
    }

    def __init__(self, response: Union[httpx.Response, dict]):
        Exception.__init__(self, InvalidGrantRequest.to_message(response))

    @staticmethod
    def to_message(response: Union[httpx.Response, dict]) -> str:
        """
        Handle response as described in:
            * https://tools.ietf.org/html/rfc6749#section-5.2
            * https://tools.ietf.org/html/rfc6749#section-4.1.2.1
            * https://tools.ietf.org/html/rfc6749#section-4.2.2.1
        """
        if isinstance(response, dict):
            return InvalidGrantRequest.to_oauth2_message(
                response, InvalidGrantRequest.browser_errors
            )

        try:
            return InvalidGrantRequest.to_oauth2_message(
                response.json(), InvalidGrantRequest.request_errors
            )
        except JSONDecodeError:
            return response.text

    @staticmethod
    def to_oauth2_message(content: dict, errors: dict) -> str:
        """
        Handle content as described in:
            * https://tools.ietf.org/html/rfc6749#section-5.2
            * https://tools.ietf.org/html/rfc6749#section-4.1.2.1
            * https://tools.ietf.org/html/rfc6749#section-4.2.2.1
        """

        def _pop(key: str) -> str:
            value = content.pop(key, None)
            if value and isinstance(value, list):
                value = value[0]
            return value

        if "error" in content:
            error = _pop("error")
            error_description = _pop("error_description") or errors.get(error)
            message = f"{error}: {error_description}"
            if "error_uri" in content:
                message += f"\nMore information can be found on {_pop('error_uri')}"
            if content:
                message += f"\nAdditional information: {content}"
        else:
            message = f"{content}"
        return message


class StateNotProvided(Exception):
    """ State was not provided. """

    def __init__(self, dictionary_without_state: dict):
        Exception.__init__(
            self, f"state not provided within {dictionary_without_state}."
        )


class TokenExpiryNotProvided(Exception):
    """ Token expiry was not provided. """

    def __init__(self, token_body: dict):
        Exception.__init__(self, f"Expiry (exp) is not provided in {token_body}.")
