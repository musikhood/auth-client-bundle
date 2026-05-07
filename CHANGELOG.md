# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-07

Wersja zsynchronizowana z auth serverem `editor_v3_backend@797be72`, gdzie
displayName został wprowadzony jako pełnoprawne pole encji użytkownika,
a `/api/v1/user/me` rozszerzono o panel context i flagę `disabled`.

### Breaking changes

- **`JwtClaims::$username` zmienione na `JwtClaims::$displayName`.**
  Konsumenci paczki nie wołają `JwtClaims` bezpośrednio, więc upgrade nie
  wymaga zmian w kodzie aplikacji — jedynie schemat tabeli `users` musi
  mieć kolumnę `display_name` (`docs/example-migration.sql` od początku
  miał, ale przy upgrade z v0.1.x sprawdź jeśli używałeś własnej migracji).
- **`JwtCookieAuthenticator` przestaje sprawdzać lokalne
  `$user->isDisabled()` przy authenticate.** Gating disabled userów jest
  teraz robiony wyłącznie przez `AuthValidationListener` po udanym `/me`
  (cache TTL ~30s). Rozwiązuje to dotychczasowy lock-in: po odblokowaniu
  konta w panelu admin auth servera użytkownik znowu działa bez konieczności
  ponownego logowania.
- **`UserData` ma 5 nowych wymaganych pól w konstruktorze**: `displayName`,
  `panelId`, `panelName`, `panelRoles`, `disabled`. Konsumenci paczki nie
  konstruują tego DTO, więc nie ma to praktycznych konsekwencji — paczka
  parsuje payload `/me` wewnętrznie.

### Added

- `UserMirrorSyncer::syncFromMe(UserData)` — pełna synchronizacja lokalnej
  kopii użytkownika z payloadu `/api/v1/user/me`. Aktualizuje displayName,
  role per-panel i flagę disabled.
- `AuthValidationListener` po udanym `/me` woła `syncFromMe()` —
  zmiany w panelu admin auth servera (zmiana ról, displayName,
  blokada/odblokowanie) propagują się do mikroserwisu w czasie cache TTL
  (~30s) bez konieczności podbijania `tokenVersion`.
- `MeController` wystawia teraz pole `displayName` w odpowiedzi `/api/v1/user/me`.
- `AuthValidationListener` odrzuca request 401 gdy `/me` zwraca 200 z
  `disabled: true` (token jeszcze ważny, ale konto zablokowane). Front
  interceptor odpali wtedy `/api/token/refresh`, który auth server odrzuci
  i wyczyści ciasteczka.

### Changed

- `JwtValidator` czyta `display_name` z claimu, z fallbackiem na `username`
  dla starszych tokenów wystawionych przed migracją auth servera.
- `AuthBackendClient::buildUserData` parsuje pełny payload `/me`
  (displayName, panelId, panelName, panelRoles, disabled).

## [0.1.3] - 2026-05-07

### Fixed

- `composer require musikhood/auth-client-bundle` nie wywala już błędu
  "Cannot autowire `PanelUserRepositoryInterface`" przy automatycznym
  `cache:clear` w post-install. Bundle rejestruje teraz stub
  (`MissingPanelUserRepository`) jeśli konsument nie podpiął jeszcze
  swojej implementacji repo. Stub rzuca jasny `RuntimeException`
  z polskim komunikatem dopiero przy pierwszym realnym użyciu auth flow,
  kierując do README. Po dodaniu `#[AsAlias]` (lub aliasu w
  `services.yaml`) Symfony automatycznie używa prawdziwego repo —
  stub jest nadpisywany przy najbliższym `cache:clear`.

## [0.1.2] - 2026-05-06

### Changed

- README, dokumentacja w `docs/` i post-install message Flex recipe
  przetłumaczone na język polski.
- Przykładowe `UserRepository` z `docs/example-repository.php` używa teraz
  atrybutu `#[AsAlias]` zamiast YAML-owego aliasu — wymaga Symfony 6.1+,
  zero zmian w `services.yaml` po stronie konsumenta.

## [0.1.1] - 2026-05-06

### Added

- Symfony Flex recipe at [musikhood/symfony-recipes](https://github.com/musikhood/symfony-recipes)
  automating bundle registration, default config templates, env vars and a
  post-install message listing the manual setup steps.

### Changed

- README rewritten with full installation walkthrough, complete reference
  implementations of `User` and `UserRepository`, the security.yaml snippet
  to copy by hand, and a configuration reference for every supported key.

## [0.1.0] - 2026-05-06

### Added

- Initial release, extracted from the PIM microservice's local `src/AuthClient/` module.
- Cookie-based auth flow: `/api/login`, `/api/logout`, `/api/token/refresh`, `/api/v1/user/me`.
- JWT validation via JWKS (cached, with rotation-aware refresh on unknown `kid`).
- Per-request introspection against the auth server with TTL cache and circuit breaker.
- Lazy upsert of the local user mirror on every authenticated request.
- `PanelUserInterface` and `PanelUserRepositoryInterface` contracts for the consumer
  to plug in its own ORM-backed entity and repository.
