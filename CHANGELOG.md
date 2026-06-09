# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.2] - 2026-06-09

### Fixed

- `JwtCookieAuthenticator::supports()` zwraca teraz `false`, gdy żądanie niesie
  nagłówek API tokenu (`X-Api-Token`) — ustępuje `ApiTokenAuthenticatorowi`.
  Wcześniej `supports()` był `null` (zawsze próbuj), więc po udanej autoryzacji
  API tokenem Symfony odpalał kolejny wspierający authenticator (JwtCookie),
  ten padał na „Brak ciasteczka BEARER" i nadpisywał sukces odpowiedzią 401.
  Efekt: 401 mimo ważnego API tokenu. Cookie flow bez nagłówka — bez zmian.
- Wstrzyknięto `$apiTokenHeader` (bind `%auth_client.api_token.header%`) do
  konstruktora `JwtCookieAuthenticator`.

### Added

- `Security\ApiTokenAuthenticator` — drugi sposób autoryzacji obok JWT-cookie:
  per-user-per-panel API token w nagłówku `X-Api-Token`. Klient maszynowy łączy
  się bez logowania, ciasteczek ani refreshu. `supports()` = true tylko gdy
  nagłówek obecny, więc współistnieje z `JwtCookieAuthenticator` (brak kolizji;
  bez nagłówka stary cookie flow bez zmian). Weryfikacja live przez introspekcję
  na auth serverze → rewokacja natychmiastowa. Fail-closed gdy auth server
  niedostępny. Asercja `panelId` z introspekcji == skonfigurowany `panel_id`.
- `AuthBackendClient::introspectApiToken()` — `POST /api/auth/backend/api-token/verify`
  (HTTP Basic client creds + nagłówek `X-Api-Token`). 401 → `null`, 5xx/transport
  → `AuthBackendException`.
- Konfiguracja `auth_client.api_token` (`enabled` default true, `header` default
  `X-Api-Token`, `cache_ttl` default 0 = bez cache → natychmiastowa rewokacja).
- `phpstan.neon.dist` — config dla statycznej analizy (level 8 + phpstan-symfony).

## [0.3.0] - 2026-05-28

### Added

- Webhook endpoint `POST /api/auth-client/webhook/user-invalidated` — 0s
  revocation. Auth server pushuje inwalidację usera (disable / password change /
  panel removal) zamiast czekać, aż konsument dogoni zmianę przez `/me` poll
  (~30s). Latency spada do setek ms.
- `WebhookJwtValidator` + `WebhookClaims` — verify-only walidacja webhook JWT
  (RS256, reuse `JwksProvider` z user JWT). `aud` musi dokładnie odpowiadać
  `panel_id` konsumenta; webhook do innego panelu / mirror jest odrzucony.
- `UserTokenVersionStore` — cache PSR (TTL 30d) trzymający ostatnią znaną
  `tokenVersion` per user, zasilany webhookiem.
- `JwtClaims::tokenVersion` (`?int`) — claim `ver` z user JWT; `null` dla starych
  tokenów wystawionych zanim auth server wdrożył versioning.
- `AuthValidationListener::invalidateValidatedCache()` — publiczna metoda
  resetująca cache walidacji usera (wołana przez webhook).

### Changed

- `JwtCookieAuthenticator` sprawdza claim `ver` przeciw `UserTokenVersionStore`.
  Null-safe: brak `ver` w tokenie lub brak wpisu w store = pass (no-op, `/me`
  poll dogoni inwalidację). Mismatch = 401 natychmiast.

### Migration guide

1. `composer update musikhood/auth-client-bundle`.
2. Dodaj do `config/packages/security.yaml` regułę **PRZED** catch-all `^/api`:

   ```yaml
   access_control:
       - { path: ^/api/auth-client/webhook/, roles: PUBLIC_ACCESS }
   ```

   Webhook ma własną autoryzację kryptograficzną (podpis JWT auth servera) —
   model jak weryfikacja podpisu webhooków Stripe/GitHub, NIE dziura w security.
   `JwtCookieAuthenticator` paczki działa w trybie lazy (`supports()` zwraca
   `null`), więc `PUBLIC_ACCESS` wystarcza — Symfony pomija wtedy authenticator
   dla tej ścieżki (osobny firewall nie jest potrzebny).
3. W panelu admin auth servera ustaw pole „Webhook URL" dla swojego panelu na
   bazowy URL swojego backendu (np. `https://pim.vitkac.com`). Auth server
   dokleja ścieżkę `/api/auth-client/webhook/user-invalidated`.
4. Upewnij się, że `cache.app` jest skonfigurowane (Redis zalecany — współdzieli
   stan między procesami i przeżywa restart).
5. Monolog tip: jeśli używasz `fingers_crossed` z `action_level: error` (typowy
   prod default), logi `webhook.received` (info) będą buforowane i tracone, gdy
   webhook kończy się 200 OK. Żeby je widzieć, dodaj osobny handler/channel ze
   `stream` do `php://stderr` na poziomie `info`.

## [0.2.5] - 2026-05-19

### Fixed

- 403 z auth servera (brak dostępu do panelu, konto disabled) zwracało
  do frontu 503 "Usługa uwierzytelniania niedostępna" — myląca informacja,
  bo usługa działała poprawnie i to user nie miał uprawnień.

  Teraz `LoginController` zwraca 403 z oryginalnym komunikatem z auth
  servera (np. "Użytkownik … nie ma dostępu do panelu …" albo
  "Konto jest zablokowane."). Pozwala konsumentowi pokazać użytkownikowi
  prawdziwy powód odmowy.

### Added

- `AuthBackendForbiddenException` — nowy typ wyjątku dla 403 z auth
  servera. Niesie tekst z pola `error` w body odpowiedzi w `message`.
  Konsument może go łapać osobno od ogólnego `AuthBackendException`.
- `AuthBackendClient::extractErrorMessage()` — wewnętrzny helper
  parsujący `error` z JSON body.

## [0.2.4] - 2026-05-19

### Changed

- Spolszczone wszystkie komunikaty błędów zwracane do frontendu (pole
  `error` w response JSON). Wcześniej user widział w panelach np.
  "Unauthorized", "Invalid credentials" — teraz wraca polski tekst.

  Zmienione komunikaty:
  - `LoginController`: "Missing credentials" → "Brak loginu lub hasła.",
    "Invalid credentials" → "Nieprawidłowy login lub hasło.",
    "Authentication service unavailable" → "Usługa uwierzytelniania niedostępna.",
    "Authentication misconfigured" → "Błąd konfiguracji uwierzytelniania."
  - `RefreshTokenController`: "Unauthorized" → "Brak autoryzacji.",
    "Authentication service unavailable" → "Usługa uwierzytelniania niedostępna."
  - `JwtCookieAuthenticator` (start + onAuthenticationFailure):
    "Unauthorized" → "Brak autoryzacji."
  - `AuthValidationListener` (UnauthorizedHttpException reason):
    "Token no longer valid upstream" → "Token nie jest już ważny na serwerze uwierzytelniania.",
    "Account disabled upstream" → "Konto zostało zablokowane."

  Struktura response (klucze JSON, kody statusów) bez zmian.

## [0.2.2] - 2026-05-07

### Added

- `cookie.domain` — opcjonalny atrybut Domain dla ciasteczek BEARER i
  refresh_token. Domyślnie null (host-only). Ustaw np. `.example.com` żeby
  ciasteczka działały dla wszystkich subdomen tej parent domain. Niezbędne
  gdy front i backend są na różnych subdomenach (cross-subdomain) — bez
  Domain browser traktuje cookie z backendu jako "innego origin" i nie
  wysyła go z requestów frontu, mimo `SameSite=None; Secure`.

  Przykład: front na `app.example.com`, backend na `api.example.com` →
  ustaw `cookie.domain: .example.com` w consumer config, np. przez env
  `AUTH_COOKIE_DOMAIN`.

  Pusty string traktowany jak null (przydatne gdy env nie jest ustawione).

## [0.2.1] - 2026-05-07

### Fixed

- `UserMirrorSyncer::upsert(JwtClaims)` zachowywał się jak full update przy
  istniejącej lokalnej kopii — claimy z JWT (potencjalnie stale, bo auth
  server nie podbija tokenVersion przy zmianach ról) nadpisywały świeżo
  zsynchronizowane dane z `syncFromMe()`. Objawiało się migotaniem ról
  między requestami: po `F5` świeże role z `/me`, po kolejnym `F5` —
  stare role z JWT.
  Teraz `upsert()` jest **bootstrap only** — przy istniejącej kopii zwraca
  ją bez zmian. Pełna synchronizacja jest wyłączną odpowiedzialnością
  `AuthValidationListener` → `syncFromMe()` (cache TTL ~30 s).

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
