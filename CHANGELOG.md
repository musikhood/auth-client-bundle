# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-06

### Added

- Initial release, extracted from the PIM microservice's local `src/AuthClient/` module.
- Cookie-based auth flow: `/api/login`, `/api/logout`, `/api/token/refresh`, `/api/v1/user/me`.
- JWT validation via JWKS (cached, with rotation-aware refresh on unknown `kid`).
- Per-request introspection against the auth server with TTL cache and circuit breaker.
- Lazy upsert of the local user mirror on every authenticated request.
- `PanelUserInterface` and `PanelUserRepositoryInterface` contracts for the consumer
  to plug in its own ORM-backed entity and repository.
