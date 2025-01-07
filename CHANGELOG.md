# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.23.0] - 2025-01-07
### Fixed
- Bearer tokens with nested JSON string are now properly handled. Thanks to [`Patrick Rodrigues`](https://github.com/pythrick).
- Client credentials auth instances will now use credentials (client_id and client_secret) as well to distinguish tokens. This was an issue when the only parameters changing were the credentials.

### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.28.\*
- Exceptions issued by `httpx_auth` are now inheriting from `httpx_auth.HttpxAuthException`, itself inheriting from `httpx.HTTPError`, instead of `Exception`.

### Added
- Explicit support for python `3.13`.

## [0.22.0] - 2024-03-02
### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.27.\*
- `httpx_auth.JsonTokenFileCache` and `httpx_auth.TokenMemoryCache` `get_token` method does not handle kwargs anymore, the `on_missing_token` callable does not expect any arguments anymore.

## [0.21.0] - 2024-02-19
### Added
- Publicly expose `httpx_auth.SupportMultiAuth`, allowing multiple authentication support for every `httpx` authentication class that exists.
- Publicly expose `httpx_auth.TokenMemoryCache`, allowing to create custom Oauth2 token cache based on this default implementation.
- You can now provide your own HTML success (`success_html`) and failure (`failure_html`) display via the new `OAuth2.display` shared setting. Refer to documentation for more details.
- Support for refresh tokens in the Resource Owner Password Credentials flow.
- Support for refresh tokens in the Authorization code (with and without PKCE) flow.
- Thanks to the new `redirect_uri_domain` parameter on Authorization code (with and without PKCE) and Implicit flows, you can now provide the [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) to use in the `redirect_uri` when `localhost` (the default) is not allowed.

### Changed
- Except for `httpx_auth.testing`, only direct access via `httpx_auth.` was considered publicly exposed. This is now explicit, as inner packages are now using private prefix (`_`).
  If you were relying on some classes or functions that are now internal, feel free to open an issue.
- Browser display settings have been moved to a shared setting, see documentation for more information on `httpx_auth.OAuth2.display`.
  The failure page will be displayed for 10 seconds by default instead of 5 seconds previously.
  As a result the following classes no longer expose `success_display_time` and `failure_display_time` parameters.
  - `httpx_auth.OAuth2AuthorizationCode`.
  - `httpx_auth.OktaAuthorizationCode`.
  - `httpx_auth.WakaTimeAuthorizationCode`.
  - `httpx_auth.OAuth2AuthorizationCodePKCE`.
  - `httpx_auth.OktaAuthorizationCodePKCE`.
  - `httpx_auth.OAuth2Implicit`.
  - `httpx_auth.AzureActiveDirectoryImplicit`.
  - `httpx_auth.AzureActiveDirectoryImplicitIdToken`.
  - `httpx_auth.OktaImplicit`.
  - `httpx_auth.OktaImplicitIdToken`.
- The authentication success and failure displayed in the browser were revamped to be more user-friendly. `httpx_auth.testing` was modified to accommodate this change:
  - `tab.assert_success` `expected_message` parameter was removed.
  - `tab.assert_failure` `expected_message` parameter should not be prefixed with `Unable to properly perform authentication: ` anymore and `\n` in the message should be replaced with `<br>`.
- `httpx_auth.JsonTokenFileCache` does not expose `tokens_path` or `last_save_time` attributes anymore and is also allowing `pathlib.Path` instances as cache location.
- `httpx_auth.TokenMemoryCache` does not expose `forbid_concurrent_cache_access` or `forbid_concurrent_missing_token_function_call` attributes anymore.
- `httpx_auth.JsonTokenFileCache` and `httpx_auth.TokenMemoryCache` `get_token` method now handles a new optional parameter named `on_expired_token`.

### Fixed
- `httpx_auth.OktaClientCredentials` `scope` parameter is now mandatory and does not default to `openid` anymore.
- `httpx_auth.OktaClientCredentials` will now display a more user-friendly error message in case Okta instance is not provided.
- Tokens cache `DEBUG` logs will not display tokens anymore.

## [0.20.0] - 2024-02-12
### Fixed
- Remove deprecation warnings due to usage of `utcnow` and `utcfromtimestamp`. Thanks to [`Raphael Krupinski`](https://github.com/rafalkrupinski).
- `httpx_auth.AWS4Auth.default_include_headers` value kept growing in size every time a new `httpx_auth.AWS4Auth` instance was created with `security_token` parameter provided. Thanks to [`Miikka Koskinen`](https://github.com/miikka).
- `httpx_auth.AWS4Auth` is now based almost entirely on AWS documentation, diverging from the original implementation based on `requests-aws4auth` and solving implementation issues in the process.
  - As the AWS documentation might be wrong or not exhaustive enough, feel free to open issues, should you encounter edge cases.

### Changed
- `httpx_auth.AWS4Auth.default_include_headers` is not available anymore, use `httpx_auth.AWS4Auth` `include_headers` parameter instead to include additional headers if the default does not fit your need (refer to documentation for an exhaustive list).
- `httpx_auth.AWS4Auth` `include_headers` values will not be stripped anymore, meaning that you can now include headers prefixed and/or suffixed with blank spaces.
- `httpx_auth.AWS4Auth` does not includes `date` header by default anymore. You will have to provide it via `include_headers` yourself if you need to.
  - Note that it should not be required as `httpx_auth.AWS4Auth` is sending `x-amz-date` by default and AWS documentation states that the request date can be specified by using either the HTTP `Date` or the `x-amz-date` header. If both headers are present, `x-amz-date` takes precedence.
- `httpx_auth.AWS4Auth` `include_headers` does not needs to include `host`, `content-type` or `x-amz-*` anymore as those headers will always be included. It is now expected to be provided as a list of additional headers.
- `httpx_auth.AWS4Auth` will not modify the headers values spaces when computing the canonical headers, only trim leading and trailing whitespaces as per AWS documentation.

## [0.19.0] - 2024-01-09
### Added
- Explicit support for Python 3.12

### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.26.\*
  - Note that this changes the signature sent via AWS auth for URLs containing %. Feel free to open an issue if this is one.

## [0.18.0] - 2023-09-11
### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.25.\*

### Removed
- Python 3.8 is no longer supported.

## [0.17.0] - 2023-04-26
### Changed
- `httpx_auth.OAuth2ResourceOwnerPasswordCredentials` does not send basic authentication by default.

### Added
- `client_auth` as a parameter of `httpx_auth.OAuth2ResourceOwnerPasswordCredentials`. Allowing to provide any kind of optional authentication.
- `httpx_auth.OktaResourceOwnerPasswordCredentials` providing Okta resource owner password credentials flow easy setup.

## [0.16.0] - 2023-04-25
### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.24.\*

### Fixed
- Handle `text/html; charset=utf-8` content-type in token responses. Thanks to [`Marcelo Trylesinski`](https://github.com/Kludex).

### Added
- `httpx_auth.WakaTimeAuthorizationCode` handling access to the [WakaTime API](https://wakatime.com/developers).

### Removed
- Python 3.7 is no longer supported.

## [0.15.0] - 2022-06-01
### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.23.\*

## [0.14.1] - 2022-02-05
### Fixed
- Type information is now provided following [PEP 561](https://www.python.org/dev/peps/pep-0561/)
- Allow for users to run `mypy --strict`.

## [0.14.0] - 2022-01-26
### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.22.\*

### Removed
- Python 3.6 is no longer supported.

## [0.13.0] - 2021-11-16
### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.21.\*

## [0.12.0] - 2021-11-01
### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.20.\*
- `OAuth2ResourceOwnerPasswordCredentials.client` attribute is now set to None in case it was not provided as parameter.
- `OAuth2ClientCredentials.client` attribute is now set to None in case it was not provided as parameter.
- `OktaClientCredentials.client` attribute is now set to None in case it was not provided as parameter.
- `OAuth2AuthorizationCode.client` attribute is now set to None in case it was not provided as parameter.
- `OktaAuthorizationCode.client` attribute is now set to None in case it was not provided as parameter.
- `OAuth2AuthorizationCodePKCE.client` attribute is now set to None in case it was not provided as parameter.
- `OktaAuthorizationCodePKCE.client` attribute is now set to None in case it was not provided as parameter.
- `httpx.Client` provided as `client` parameter to `OAuth2ResourceOwnerPasswordCredentials` is not closed anymore. You are now responsible for closing it when no more requests are expected to be issued.
- `httpx.Client` provided as `client` parameter to `OAuth2ClientCredentials` is not closed anymore. You are now responsible for closing it when no more requests are expected to be issued.
- `httpx.Client` provided as `client` parameter to `OktaClientCredentials` is not closed anymore. You are now responsible for closing it when no more requests are expected to be issued.
- `httpx.Client` provided as `client` parameter to `OAuth2AuthorizationCode` is not closed anymore. You are now responsible for closing it when no more requests are expected to be issued.
- `httpx.Client` provided as `client` parameter to `OktaAuthorizationCode` is not closed anymore. You are now responsible for closing it when no more requests are expected to be issued.
- `httpx.Client` provided as `client` parameter to `OAuth2AuthorizationCodePKCE` is not closed anymore. You are now responsible for closing it when no more requests are expected to be issued.
- `httpx.Client` provided as `client` parameter to `OktaAuthorizationCodePKCE` is not closed anymore. You are now responsible for closing it when no more requests are expected to be issued.

### Fixed
- A new client is created (if not provided as `client` parameter) upon request of a new token for `OAuth2ResourceOwnerPasswordCredentials` flow. Re-using previously closed client was raising an issue upon token expiry.
- A new client is created (if not provided as `client` parameter) upon request of a new token for `OAuth2ClientCredentials` flow. Re-using previously closed client was raising an issue upon token expiry.
- A new client is created (if not provided as `client` parameter) upon request of a new token for `OktaClientCredentials` flow. Re-using previously closed client was raising an issue upon token expiry.
- A new client is created (if not provided as `client` parameter) upon request of a new token for `OAuth2AuthorizationCode` flow. Re-using previously closed client was raising an issue upon token expiry.
- A new client is created (if not provided as `client` parameter) upon request of a new token for `OktaAuthorizationCode` flow. Re-using previously closed client was raising an issue upon token expiry.
- A new client is created (if not provided as `client` parameter) upon request of a new token for `OAuth2AuthorizationCodePKCE` flow. Re-using previously closed client was raising an issue upon token expiry.
- A new client is created (if not provided as `client` parameter) upon request of a new token for `OktaAuthorizationCodePKCE` flow. Re-using previously closed client was raising an issue upon token expiry.

## [0.11.0] - 2021-08-19
### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.19.\*

### Fixed
- Tild character (`~`) is not URL encoded anymore.

## [0.10.0] - 2021-04-27
### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.18.\*

## [0.9.0] - 2021-03-01
### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.17.\*

## [0.8.0] - 2020-11-15
### Removed
- Do not expose `httpx_auth.oauth2_tokens.decode_base64` function anymore as it supposed to be used internally only.
- Do not expose `add_bearer_token` token cache method anymore as it supposed to be used internally only.
- Do not expose `add_access_token` token cache method anymore as it supposed to be used internally only.

### Changed
- `get_token` cache method now requires `on_missing_token` function args to be provided as kwargs instead of args.
- `get_token` cache method now requires `on_missing_token` parameter to be provided as a non-positional argument.
- `get_token` cache method now expose `early_expiry` parameter, defaulting to 30 seconds.

### Fixed
- OAuth2 token will now be considered as expired 30 seconds before actual expiry. To ensure it is still valid when received by the actual server.

### Added
- `httpx_auth.OAuth2ResourceOwnerPasswordCredentials` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `httpx_auth.OAuth2ClientCredentials` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `httpx_auth.OktaClientCredentials` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `httpx_auth.OAuth2AuthorizationCode` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `httpx_auth.OktaAuthorizationCode` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `httpx_auth.OAuth2AuthorizationCodePKCE` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `httpx_auth.OktaAuthorizationCodePKCE` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `httpx_auth.OAuth2Implicit` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `httpx_auth.AzureActiveDirectoryImplicit` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `httpx_auth.AzureActiveDirectoryImplicitIdToken` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `httpx_auth.OktaImplicit` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.
- `httpx_auth.OktaImplicitIdToken` contains a new `early_expiry` parameter allowing to tweak the number of seconds before actual token expiry where the token will be considered as already expired. Default to 30s.

## [0.7.0] - 2020-10-06
### Added
- Explicit support for Python 3.9
- Document `httpx_auth.AWS4Auth` authentication class.

### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.16.*
- Code now follow `black==20.8b1` formatting instead of the git master version.

## [0.6.0] - 2020-09-22
### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.15.*

## [0.5.1] - 2020-08-31
### Fixed
- `AWSAuth` authentication class now handles empty path. Thanks to [`Michael E. Martinka`](https://github.com/martinka). This class is still considered as under development and subject to breaking changes without notice.

### Changed
- All methods within `AWSAuth` are now private. They were never meant to be exposed anyway.

## [0.5.0] - 2020-08-19
### Added
- Allow to provide an `httpx.Client` instance for `*AuthorizationCode` flows (even `PKCE`), `*ClientCredentials` and `*ResourceOwnerPasswordCredentials` flows.

## [0.4.0] - 2020-08-07
### Changed
- Mock an access token by default in `httpx_auth.testing.token_cache_mock`. Getting rid of `pyjwt` default dependency for testing.
- Requires [`httpx`](https://www.python-httpx.org)==0.14.*

### Added
- Still under development, subject to breaking changes without notice: `AWS4Auth` authentication class for AWS. Ported from [`requests-aws4auth`](https://github.com/sam-washington/requests-aws4auth) by [`Michael E. Martinka`](https://github.com/martinka).
Note that a few changes were made:
  - Deprecated `amz_date` attribute has been removed.
  - It is not possible to provide an `AWSSigningKey` instance, use explicit parameters instead.
  - It is not possible to provide a `date`. It will default to now.
  - It is not possible to provide `raise_invalid_date` parameter anymore as the date will always be valid.
  - `include_hdrs` parameter was renamed into `include_headers`
  - `host` is not considered as a specific Amazon service anymore (no test specific code).
  - Each request now has its own signing key and `x-amz-date`. Meaning you can use the same auth instance for more than one request.
  - `session_token` was renamed into `security_token` for consistency with the underlying name at Amazon.

## [0.3.0] - 2020-05-26
### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.13.*

## [0.2.0] - 2020-03-23
### Removed
- Deprecated `httpx_auth.Auths` class has been removed.

## [0.1.0] - 2020-03-09
### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.12.*

## [0.0.2] - 2020-02-10
### Added
- Port of requests_auth 5.0.2 for httpx

## [0.0.1] - 2020-02-04
### Added
- Placeholder for port of requests_auth to httpx

[Unreleased]: https://github.com/Colin-b/httpx_auth/compare/v0.23.0...HEAD
[0.23.0]: https://github.com/Colin-b/httpx_auth/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/Colin-b/httpx_auth/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/Colin-b/httpx_auth/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/Colin-b/httpx_auth/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/Colin-b/httpx_auth/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/Colin-b/httpx_auth/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/Colin-b/httpx_auth/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/Colin-b/httpx_auth/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/Colin-b/httpx_auth/compare/v0.14.1...v0.15.0
[0.14.1]: https://github.com/Colin-b/httpx_auth/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/Colin-b/httpx_auth/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/Colin-b/httpx_auth/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/Colin-b/httpx_auth/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/Colin-b/httpx_auth/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/Colin-b/httpx_auth/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/Colin-b/httpx_auth/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/Colin-b/httpx_auth/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/Colin-b/httpx_auth/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/Colin-b/httpx_auth/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/Colin-b/httpx_auth/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Colin-b/httpx_auth/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Colin-b/httpx_auth/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Colin-b/httpx_auth/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Colin-b/httpx_auth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Colin-b/httpx_auth/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/Colin-b/httpx_auth/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/Colin-b/httpx_auth/releases/tag/v0.0.1
