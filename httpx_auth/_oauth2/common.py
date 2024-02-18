from typing import Optional
from urllib.parse import parse_qs, urlsplit, urlunsplit, urlencode

import httpx

from httpx_auth._errors import GrantNotProvided, InvalidGrantRequest
from httpx_auth._oauth2.browser import DisplaySettings
from httpx_auth._oauth2.tokens import TokenMemoryCache


def _add_parameters(initial_url: str, extra_parameters: dict) -> str:
    """
    Add parameters to a URL and return the new URL.

    :param initial_url:
    :param extra_parameters: dictionary of parameters names and value.
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


def _content_from_response(response: httpx.Response) -> dict:
    content_type = response.headers.get("content-type")
    if content_type == "text/html; charset=utf-8":
        return {
            key_values[0]: key_values[1]
            for key_value in response.text.split("&")
            if (key_values := key_value.split("=")) and len(key_values) == 2
        }
    return response.json()


def request_new_grant_with_post(
    url: str, data, grant_name: str, client: httpx.Client
) -> (str, int, str):
    response = client.post(url, data=data)

    if response.is_error:
        # As described in https://tools.ietf.org/html/rfc6749#section-5.2
        raise InvalidGrantRequest(response)

    content = _content_from_response(response)
    token = content.get(grant_name)
    if not token:
        raise GrantNotProvided(grant_name, content)
    return token, content.get("expires_in"), content.get("refresh_token")


class OAuth2:
    token_cache = TokenMemoryCache()
    display = DisplaySettings()
