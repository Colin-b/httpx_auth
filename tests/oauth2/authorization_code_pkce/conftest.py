import pytest

import httpx_auth._oauth2.authorization_code_pkce


@pytest.fixture(autouse=True)
def urandom_patch(monkeypatch):
    monkeypatch.setattr(
        httpx_auth._oauth2.authorization_code_pkce.os, "urandom", lambda x: b"1" * 63
    )
