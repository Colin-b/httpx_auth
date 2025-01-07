import base64
import json
import os
import datetime
import threading
import logging
from pathlib import Path
from typing import Union, Optional

from httpx_auth._errors import (
    InvalidToken,
    TokenExpiryNotProvided,
    AuthenticationFailed,
    InvalidGrantRequest,
    GrantNotProvided,
)

logger = logging.getLogger(__name__)


def decode_base64(base64_encoded_string: str) -> str:
    """
    Decode base64, padding being optional.

    :param base64_encoded_string: Base64 data as an ASCII byte string
    :returns: The decoded byte string.
    """
    missing_padding = len(base64_encoded_string) % 4
    if missing_padding != 0:
        base64_encoded_string += "=" * (4 - missing_padding)
    return base64.urlsafe_b64decode(base64_encoded_string).decode("utf-8")


def is_expired(expiry: float, early_expiry: float) -> bool:
    return datetime.datetime.fromtimestamp(
        expiry - early_expiry, datetime.timezone.utc
    ) < datetime.datetime.now(datetime.timezone.utc)


def to_expiry(expires_in: Union[int, str]) -> float:
    expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        seconds=int(expires_in)
    )
    return expiry.timestamp()


class TokenMemoryCache:
    """
    Class to manage tokens using memory storage.
    """

    def __init__(self):
        self.tokens = {}
        self._forbid_concurrent_cache_access = threading.Lock()
        self._forbid_concurrent_missing_token_function_call = threading.Lock()

    def _add_bearer_token(self, key: str, token: str) -> None:
        """
        Set the bearer token and save it
        :param key: key identifier of the token
        :param token: value
        :raise InvalidToken: In case token is invalid.
        :raise TokenExpiryNotProvided: In case expiry is not provided.
        """
        if not token:
            raise InvalidToken(token)

        header, body, other = token.split(".")
        body = json.loads(decode_base64(body))
        expiry = body.get("exp")
        if not expiry:
            raise TokenExpiryNotProvided(expiry)

        self._add_token(key, token, expiry)

    def _add_access_token(
        self,
        key: str,
        token: str,
        expires_in: Union[int, str],
        refresh_token: Optional[str] = None,
    ) -> None:
        """
        Set the bearer token and save it
        :param key: key identifier of the token
        :param token: value
        :param expires_in: Number of seconds before token expiry
        :raise InvalidToken: In case token is invalid.
        """
        self._add_token(key, token, to_expiry(expires_in), refresh_token)

    def _add_token(
        self, key: str, token: str, expiry: float, refresh_token: Optional[str] = None
    ) -> None:
        """
        Set the bearer token and save it
        :param key: key identifier of the token
        :param token: value
        :param expiry: UTC timestamp of expiry
        :param refresh_token: refresh token value
        """
        with self._forbid_concurrent_cache_access:
            self.tokens[key] = token, expiry, refresh_token
            self._save_tokens()
            logger.debug(
                "Inserting token expiring on"
                f' {datetime.datetime.fromtimestamp(expiry, datetime.timezone.utc)} with "{key}" key.'
            )

    def get_token(
        self,
        key: str,
        *,
        early_expiry: float = 30.0,
        on_missing_token=None,
        on_expired_token=None,
    ) -> str:
        """
        Return the bearer token.
        :param key: key identifier of the token
        :param early_expiry: As the time between the token extraction from cache and the token reception on server side
        might not higher than one second, on slow networks, token might be expired when received by the actual server,
        even if still valid when fetched.
        This is the number of seconds to subtract to the actual token expiry. Token will be considered as
        expired 30 seconds before real expiry by default.
        :param on_missing_token: function to call when token is expired or missing (returning token and expiry tuple)
        :param on_expired_token: function to call to refresh the token when it is expired
        :return: the token
        :raise AuthenticationFailed: in case token cannot be retrieved.
        """
        logger.debug(f'Retrieving token with "{key}" key.')
        refresh_token = None
        with self._forbid_concurrent_cache_access:
            self._load_tokens()
            if key in self.tokens:
                token = self.tokens[key]
                if len(token) == 2:  # No refresh token
                    bearer, expiry = token
                else:
                    bearer, expiry, refresh_token = token
                if is_expired(expiry, early_expiry):
                    logger.debug(f'Authentication token with "{key}" key is expired.')
                    del self.tokens[key]
                else:
                    logger.debug(
                        "Using already received authentication, will expire on"
                        f" {datetime.datetime.fromtimestamp(expiry, datetime.timezone.utc)}."
                    )
                    return bearer

        if refresh_token is not None and on_expired_token is not None:
            try:
                with self._forbid_concurrent_missing_token_function_call:
                    state, token, expires_in, refresh_token = on_expired_token(
                        refresh_token
                    )
                    self._add_access_token(state, token, expires_in, refresh_token)
                    logger.debug(f"Refreshed token with key {key}.")
                with self._forbid_concurrent_cache_access:
                    if state in self.tokens:
                        bearer, expiry, refresh_token = self.tokens[state]
                        logger.debug(
                            f"Using newly refreshed token, expiring on {datetime.datetime.fromtimestamp(expiry, datetime.timezone.utc)}."
                        )
                        return bearer
            except (InvalidGrantRequest, GrantNotProvided):
                logger.debug("Failed to refresh token.")

        logger.debug("Token cannot be found in cache.")
        if on_missing_token is not None:
            with self._forbid_concurrent_missing_token_function_call:
                new_token = on_missing_token()
                if len(new_token) == 2:  # Bearer token
                    state, token = new_token
                    self._add_bearer_token(state, token)
                elif len(new_token) == 3:  # Access token
                    state, token, expires_in = new_token
                    self._add_access_token(state, token, expires_in)
                else:  # Access Token and Refresh token
                    state, token, expires_in, refresh_token = new_token
                    self._add_access_token(state, token, expires_in, refresh_token)
                if key != state:
                    logger.warning(
                        f"Using a token received on another key than expected. Expecting {key} but was {state}."
                    )
            with self._forbid_concurrent_cache_access:
                if state in self.tokens:
                    bearer, expiry, refresh_token = self.tokens[state]
                    logger.debug(
                        "Using newly received authentication, expiring on"
                        f" {datetime.datetime.fromtimestamp(expiry, datetime.timezone.utc)}."
                    )
                    return bearer

        logger.debug(
            f"User was not authenticated: key {key} cannot be found in {list(self.tokens)}."
        )
        raise AuthenticationFailed()

    def clear(self) -> None:
        """Remove tokens from the cache."""
        with self._forbid_concurrent_cache_access:
            logger.debug("Clearing token cache.")
            self.tokens = {}
            self._clear()

    def _save_tokens(self) -> None:
        pass

    def _load_tokens(self) -> None:
        pass

    def _clear(self) -> None:
        pass


class JsonTokenFileCache(TokenMemoryCache):
    """
    Class to manage tokens using a cache file.
    """

    def __init__(self, tokens_path: Union[str, Path]):
        TokenMemoryCache.__init__(self)
        self._tokens_path = Path(tokens_path)
        self._last_save_time = 0
        self._load_tokens()

    def _clear(self) -> None:
        self._last_save_time = 0
        try:
            self._tokens_path.unlink(missing_ok=True)
        except:
            logger.debug("Cannot remove tokens file.")

    def _save_tokens(self) -> None:
        try:
            with self._tokens_path.open(mode="w") as tokens_cache_file:
                json.dump(self.tokens, tokens_cache_file)
            self._last_save_time = os.path.getmtime(self._tokens_path)
        except:
            logger.exception("Cannot save tokens.")

    def _load_tokens(self) -> None:
        if not self._tokens_path.exists():
            logger.debug("No token loaded. Token cache does not exists.")
            return
        try:
            last_modification_time = os.path.getmtime(self._tokens_path)
            if last_modification_time > self._last_save_time:
                self._last_save_time = last_modification_time
                with self._tokens_path.open(mode="r") as tokens_cache_file:
                    self.tokens = json.load(tokens_cache_file)
        except:
            logger.exception("Cannot load tokens.")
