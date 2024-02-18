import datetime

import pytest
import jwt

import httpx_auth
import httpx_auth._oauth2.tokens


@pytest.fixture
def token_cache(tmp_path):
    _token_cache = httpx_auth.JsonTokenFileCache(tmp_path / "my_tokens.cache")
    yield _token_cache
    _token_cache.clear()


def test_add_bearer_tokens(token_cache):
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token1 = jwt.encode({"exp": expiry_in_1_hour}, "secret")
    token_cache._add_bearer_token("key1", token1)

    expiry_in_2_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=2)
    token2 = jwt.encode({"exp": expiry_in_2_hour}, "secret")
    token_cache._add_bearer_token("key2", token2)

    # Assert that tokens can be retrieved properly even after other token were inserted
    assert token_cache.get_token("key1") == token1
    assert token_cache.get_token("key2") == token2

    # Assert that tokens are not removed from the cache on retrieval
    assert token_cache.get_token("key1") == token1
    assert token_cache.get_token("key2") == token2


def test_save_bearer_tokens(token_cache, tmp_path):
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token1 = jwt.encode({"exp": expiry_in_1_hour}, "secret")
    token_cache._add_bearer_token("key1", token1)

    expiry_in_2_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=2)
    token2 = jwt.encode({"exp": expiry_in_2_hour}, "secret")
    token_cache._add_bearer_token("key2", token2)

    same_cache = httpx_auth.JsonTokenFileCache(tmp_path / "my_tokens.cache")
    assert same_cache.get_token("key1") == token1
    assert same_cache.get_token("key2") == token2


def test_save_bearer_token_exception_handling(token_cache, tmp_path, monkeypatch):
    def failing_dump(*args):
        raise Exception("Failure")

    monkeypatch.setattr(httpx_auth._oauth2.tokens.json, "dump", failing_dump)

    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token1 = jwt.encode({"exp": expiry_in_1_hour}, "secret")

    # Assert that the exception is not thrown
    token_cache._add_bearer_token("key1", token1)

    same_cache = httpx_auth.JsonTokenFileCache(tmp_path / "my_tokens.cache")
    with pytest.raises(httpx_auth.AuthenticationFailed) as exception_info:
        same_cache.get_token("key1")
    assert str(exception_info.value) == "User was not authenticated."


def test_missing_token(token_cache):
    with pytest.raises(httpx_auth.AuthenticationFailed):
        token_cache.get_token("key1")


def test_missing_token_function(token_cache):
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    token = jwt.encode({"exp": expiry_in_1_hour}, "secret")
    retrieved_token = token_cache.get_token(
        "key1", on_missing_token=lambda: ("key1", token)
    )
    assert retrieved_token == token


def test_token_without_refresh_token(token_cache):
    expiry_in_1_hour = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(hours=1)
    # add token without refresh token
    token = jwt.encode({"exp": expiry_in_1_hour}, "secret")
    token_cache.tokens["key1"] = (
        token,
        expiry_in_1_hour.replace(tzinfo=datetime.timezone.utc).timestamp(),
    )
    token_cache._save_tokens()

    # try to retrieve it
    retrieved_token = token_cache.get_token("key1")
    assert token == retrieved_token
