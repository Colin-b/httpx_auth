import typing
from typing import Generator

import httpx
from httpx import Request, Response


class _MultiAuth(httpx.Auth):
    """Authentication using multiple authentication methods."""

    def __init__(self, *authentication_modes):
        self.authentication_modes = authentication_modes

    def sync_auth_flow(
        self, request: Request
    ) -> typing.Generator[Request, Response, None]:
        for authentication_mode in self.authentication_modes:
            # auth_flow may yield one or more requests, the last of which is the user request with added auth headers
            flow = authentication_mode.sync_auth_flow(request)
            req = next(flow)
            while True:
                if req is request:
                    break
                resp = yield req
                req = flow.send(resp)
        yield request

    async def async_auth_flow(
        self, request: Request
    ) -> typing.AsyncGenerator[Request, Response]:
        for authentication_mode in self.authentication_modes:
            # auth_flow may yield one or more requests, the last of which is the user request with added auth headers
            flow = authentication_mode.async_auth_flow(request)
            req = await anext(flow)
            while True:
                if req is request:
                    break
                resp = yield req
                req = await flow.asend(resp)
        yield request

    def __add__(self, other) -> "_MultiAuth":
        if isinstance(other, _MultiAuth):
            return _MultiAuth(*self.authentication_modes, *other.authentication_modes)
        return _MultiAuth(*self.authentication_modes, other)

    def __and__(self, other) -> "_MultiAuth":
        if isinstance(other, _MultiAuth):
            return _MultiAuth(*self.authentication_modes, *other.authentication_modes)
        return _MultiAuth(*self.authentication_modes, other)


class SupportMultiAuth:
    """Inherit from this class to be able to use your class with httpx_auth provided authentication classes."""

    def __add__(self, other) -> _MultiAuth:
        if isinstance(other, _MultiAuth):
            return _MultiAuth(self, *other.authentication_modes)
        return _MultiAuth(self, other)

    def __and__(self, other) -> _MultiAuth:
        if isinstance(other, _MultiAuth):
            return _MultiAuth(self, *other.authentication_modes)
        return _MultiAuth(self, other)


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
