from typing import Optional
from urllib.parse import parse_qs, urlsplit, urlunsplit, urlencode

import httpx

from httpx_auth._errors import GrantNotProvided, InvalidGrantRequest

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
) -> (str, int):
    response = client.post(url, data=data)

    if response.is_error:
        # As described in https://tools.ietf.org/html/rfc6749#section-5.2
        raise InvalidGrantRequest(response)

    content = _content_from_response(response)
    token = content.get(grant_name)
    if not token:
        raise GrantNotProvided(grant_name, content)
    return token, content.get("expires_in")


class DisplaySettings:
    _default_template = """<!DOCTYPE html>
<html lang="en">
    <head>
        <title>{title}</title>
        <style>
body {{
    border: none;
    box-sizing: border-box;
    display: block;
    font-family: "Segoe UI";
    font-weight: 500;
    line-height: 1.5;
    padding: 50px 0 76px 0;
    text-align: center;
}}

.content {{
    padding: 30px 0 50px 0;
}}

h1 {{
    color: {color};
    font-size: 2.4rem;
    margin: 1.7rem auto .5rem auto;
}}

p {{
    color: #2f374f;
    font-size: 1.2rem;
    margin: .75rem 0 0 0;
}}

.btn {{
    display: inline-block;
    color: {color} !important;
    text-decoration: none;
    background-color: {background_color};
    padding: 14px 24px;
    border-radius: 8px;
    font-size: 1em;
    font-weight: 400;
    margin: 50px 0 0 0;
}}

.btn:hover {{
    color: {background_color} !important;
    background-color: {color};
}}

@keyframes zoomText {{
  from {{
    opacity: 0;
    transform: scale3d(0.9, 0.9, 0.9);
  }}
  50% {{
    opacity: 1;
  }}
}}

.content h1 {{
    animation-duration: .6s;
    animation-fill-mode: both;
    animation-name: zoomText;
    animation-delay: .2s;
}}
        </style>
    </head>
    <body onload="window.open('', '_self', ''); window.setTimeout(close, {display_time})">
        <div class="content">
            <h1>{title}</h1>
            <p>{information}</p>
        </div>
        <div class="more">
            <a href="https://colin-b.github.io/httpx_auth/" class="btn" target="_blank" rel="noreferrer noopener" role="button">Documentation</a>
            <a href="https://github.com/Colin-b/httpx_auth/blob/develop/CHANGELOG.md" class="btn" target="_blank" rel="noreferrer noopener" role="button">Latest changes</a>
        </div>
    </body>
</html>"""
    _default_success = (
        _default_template.replace("{title}", "Authentication success")
        .replace("{color}", "#32cd32")
        .replace("{background_color}", "#f0fff0")
        .replace("{information}", "You can close this tab")
    )
    _default_failure = (
        _default_template.replace("{title}", "Authentication failed")
        .replace("{color}", "#dc143c")
        .replace("{background_color}", "#fffafa")
    )

    def __init__(
        self,
        *,
        success_display_time: int = 1,
        success_template: str = None,
        failure_display_time: int = 5000,
        failure_template: str = None,
    ):
        """
        :param success_display_time: In case a code/token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param success_template: In case a code or token is successfully received,
        this is the success page that will be displayed in your browser.
        `{display_time}` is expected in this content.
        :param failure_display_time: In case received code/token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 5 seconds by default.
        :param failure_template: In case received code or token is not valid,
        this is the failure page that will be displayed in your browser.
        `{information}` and `{display_time}` are expected in this content.
        """
        # Time is expressed in milliseconds
        self.success_display_time = success_display_time
        self.success_template = success_template or self._default_success

        # Time is expressed in milliseconds
        self.failure_display_time = failure_display_time
        self.failure_template = failure_template or self._default_failure


class OAuth2:
    token_cache = TokenMemoryCache()
    display = DisplaySettings()


class BrowserAuth:
    def __init__(self, kwargs):
        """
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://localhost:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 code will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a code or a token to be received once requested.
        Wait for 1 minute (60 seconds) by default.
        """
        redirect_uri_endpoint = kwargs.pop("redirect_uri_endpoint", None) or ""
        self.redirect_uri_port = int(kwargs.pop("redirect_uri_port", None) or 5000)
        self.redirect_uri = (
            f"http://localhost:{self.redirect_uri_port}/{redirect_uri_endpoint}"
        )

        # Time is expressed in seconds
        self.timeout = float(kwargs.pop("timeout", None) or 60)
