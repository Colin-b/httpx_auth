# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Changed
- Mock an access token by default in `httpx_auth.testing.token_cache_mock`. Getting rid of `pyjwt` default dependency for testing.
- Requires [`httpx`](https://www.python-httpx.org)==0.14.*

### Added
- `AWS4Auth` and `StrictAWS4` authentication classes for AWS. Ported from [`requests-aws4auth`](https://github.com/sam-washington/requests-aws4auth) by [`Michael E. Martinka`](https://github.com/martinka).
Note that a few changes were made:
  - deprecated `amz_date` attribute has been removed.

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

[Unreleased]: https://github.com/Colin-b/httpx_auth/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Colin-b/httpx_auth/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Colin-b/httpx_auth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Colin-b/httpx_auth/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/Colin-b/httpx_auth/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/Colin-b/httpx_auth/releases/tag/v0.0.1
