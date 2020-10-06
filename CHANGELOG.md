# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
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

[Unreleased]: https://github.com/Colin-b/httpx_auth/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/Colin-b/httpx_auth/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/Colin-b/httpx_auth/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Colin-b/httpx_auth/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Colin-b/httpx_auth/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Colin-b/httpx_auth/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Colin-b/httpx_auth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Colin-b/httpx_auth/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/Colin-b/httpx_auth/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/Colin-b/httpx_auth/releases/tag/v0.0.1
