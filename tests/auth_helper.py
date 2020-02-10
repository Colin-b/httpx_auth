import httpx
import httpx.auth
from pytest_httpx import HTTPXMock


# TODO Remove
def get_header(httpx_mock: HTTPXMock, auth: httpx.auth.Auth) -> dict:
    # Mock a dummy response
    httpx_mock.add_response()
    # Send a request to this dummy URL with authentication
    response = httpx.get("http://authorized_only", auth=auth)
    # Return headers received on this dummy URL
    return response.request.headers
