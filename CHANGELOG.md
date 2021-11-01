# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.12.0] - 2021-11-01
### Changed
- Requires [`httpx`](https://www.python-httpx.org)==0.20.\*

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
- `get_token` cache method now requires `on_missing_token` parameter to be provided as a non positional argument.
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
  - deprecated `amz_date` attribute has been removed.
  - it is not possible to provide an `AWSSigningKey` instance, use explicit parameters instead.
  - it is not possible to provide a `date`. It will default to now.
  - it is not possible to provide `raise_invalid_date` parameter anymore as the date will always be valid.
  - `include_hdrs` parameter was renamed into `include_headers`
  - `host` is not considered as a specific Amazon service anymore (no test specific code).
  - Each request now has it's own signing key and x-amz-date. Meaning you can use the same auth instance for more than one request.
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

[Unreleased]: https://github.com/Colin-b/httpx_auth/compare/v0.12.0...HEAD
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
