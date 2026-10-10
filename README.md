# auth-client-bundle

Symfony bundle dla paneli, które delegują uwierzytelnianie do auth servera
(API Core / editor_v3_backend): logowanie, 2FA, refresh, wylogowanie, JWT/JWKS,
ciasteczka HttpOnly (`BEARER` + `refresh_token`) i introspekcja sesji z circuit
breakerem. Front (`@musikhood-dev/auth-client`) nigdy nie widzi JWT.

Od **0.8** paczka działa bez konfiguracji: integrator podaje tylko dane panelu
w env, a `auth-client:install` + `auth-client:doctor` robią resztę.
Pełna checklista podpięcia panelu (admin → backend → front → 2FA → problemy):
**[INTEGRATION.md](INTEGRATION.md)**.

## Quick start (5 minut)

1. **Admin** tworzy panel w auth-panelu (origin frontu, webhook URL = URL backendu panelu) i zapisuje
   `panel_id`, `client_id`, `client_secret` w bazie dostępów Work HUB.
2. Instalacja paczki:
   ```bash
   composer require musikhood/auth-client-bundle:^0.8
   ```
3. Dane panelu do `.env.local` (lokalnie) / sekretu k8s — z bazy dostępów Work HUB (`secret_to_env`):
   `AUTH_PANEL_ID`, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`. `AUTH_BASE_URL` jest opcjonalny —
   domyślnie `https://editor-v3-backend.vitkac.com`, jedyny auth server (master) **także dla paneli dev**
   (instancja dev API Core to mirror bez endpointów `/api/auth/backend/*`).
4. Konfiguracja security, CORS, tras i trusted proxies (pokazuje zmiany i pyta przed zapisem):
   ```bash
   bin/console auth-client:install
   ```
5. Weryfikacja — ma być zielono:
   ```bash
   bin/console auth-client:doctor
   ```
6. Front: `npm i @musikhood-dev/auth-client` i `npx @musikhood-dev/auth-client init`
   ([README paczki](https://github.com/musikhood/auth-client#quick-start-5-minut)).

Gotowe. Nie potrzebujesz encji `User`, tabeli ani migracji (tryb bezstanowy). Polityka 2FA
(`off` / `optional` / `required`) i device binding — wyłącznie w auth-panelu.

> **Endpoint Flex jest opcjonalny.** Bez niego Flex i tak rejestruje bundle w `config/bundles.php`,
> a `auth-client:install` dopisuje import tras i klucze `AUTH_*` do `.env`. Jeśli chcesz recipe
> (gotowy `auth_client.yaml` z 4 liniami env i komunikat po instalacji), raz w projekcie:
> ```bash
> composer config --json extra.symfony.endpoint '["https://api.github.com/repos/musikhood/symfony-recipes/contents/index.json","flex://defaults"]'
> ```

## Jak działa

```
przeglądarka ──cookies──▶ backend panelu (ten bundle) ──HTTP Basic (client_id/secret)──▶ auth server (API Core)
                          │  /api/login, /api/login/mfa, /api/session/mfa, /api/token/refresh, /api/logout
                          │  JWT z ciasteczka BEARER → podpis z JWKS (offline)
                          └─ co ≤30 s / user: introspekcja → dostęp do panelu, polityka 2FA, role
```

- **Logowanie**: front woła `/api/login` w backendzie panelu; bundle forwarduje do auth servera
  (`/api/auth/backend/login`) i ustawia ciasteczka HttpOnly. Kroki 2FA (`mfa_required`,
  `mfa_enrollment_required`, step-up) przechodzą do frontu 1:1.
- **Każdy request**: `JwtCookieAuthenticator` weryfikuje JWT offline (JWKS), a `AuthValidationListener`
  co `validation_cache_ttl` (30 s) pyta auth server, czy sesja żyje, czy user ma dostęp do TEGO panelu
  i czy spełnia politykę 2FA panelu. 401 = sesja martwa (front robi refresh), 403 = brak dostępu / 2FA.
- **User**: domyślnie **bezstanowy** — budowany z JWT i introspekcji, snapshot w `cache.app`
  (role zmienione w auth-panelu docierają w ≤30 s). Opcjonalnie własna tabela userów
  („[Lokalna kopia userów](#opcjonalnie-lokalna-kopia-userów-encja--tabela)”).
- **Trasy publiczne** (jedno źródło w kodzie: `Musikhood\AuthClient\Routing\PublicRoutes`):
  `/api/login`, `/api/login/mfa`, `/api/logout`, `/api/token/refresh`, `/api/token/invalidate`,
  `/api/session/mfa`, `/api/mfa/enrollment/request`, `/api/auth-client/webhook/user-invalidated`.
  Reszta `^/api` wymaga zalogowania.

## Komendy

### `bin/console auth-client:install`

Opcje: `--dry-run` (tylko pokaż), `--yes` (zapisz bez pytania), `--no-doctor`.

| Plik | Co robi |
|---|---|
| `.env` | dopisuje `AUTH_BASE_URL` (prod), puste `AUTH_PANEL_ID/CLIENT_ID/CLIENT_SECRET` (z komentarzem o bazie dostępów) i `SYMFONY_TRUSTED_PROXIES=private_ranges` — tylko klucze, których nie ma w `.env` ani w środowisku (`.env.local`, sekrety) |
| `config/routes/auth_client.yaml` | import tras bundla (jeśli nigdzie go nie ma) |
| `config/packages/security.yaml` | brak pliku / domyślny plik Symfony → pełna konfiguracja (sekcje `when@*` zachowane); **własne firewalle → nic nie nadpisuje**: sprawdza pokrycie tras bundla (kolejność jak w Symfony) i jeśli czegoś brakuje, wypisuje dokładny fragment do wklejenia |
| `config/packages/nelmio_cors.yaml` | (jeśli jest NelmioCorsBundle) `allow_credentials: true`, `allow_headers` += `X-Device-Fp`, `expose_headers` += `Retry-After`; plik, którego nie da się bezpiecznie edytować → fragment do wklejenia; brak Nelmio → instrukcja |
| `config/packages/framework.yaml` | tylko Symfony < 7.2: `trusted_proxies: '%env(default::SYMFONY_TRUSTED_PROXIES)%'` (7.2+ czyta env sam) |

Na końcu uruchamia `auth-client:doctor` (po zapisie — w nowym procesie, z nową konfiguracją).
Drugie uruchomienie nic nie zmienia.

### `bin/console auth-client:doctor`

Sprawdza i wypisuje ✔ / ! / ✘ z podpowiedzią, co zrobić (exit code ≠ 0 przy błędzie — nadaje się
do CI / smoke testu po deployu). Nigdy nie wypisuje sekretów.

- konfiguracja: env ustawione i niepuste, `panel_id` to UUID;
- auth server osiągalny (`/.well-known/jwks.json`), poprawne `client_id`/`client_secret`
  (introspekcja bez tokenu: zły Basic = 401 z `WWW-Authenticate`), auth server ma trasy 2FA;
- `panel_id` zgodny z klientem — z `--access-token=<wartość ciasteczka BEARER>` (introspekcja prawdziwej sesji);
- security: wszystkie trasy publiczne bez logowania, `^/api` za `JwtCookieAuthenticator` i `IS_AUTHENTICATED_FULLY`
  (na żywej konfiguracji, po `cache:clear`);
- CORS (Nelmio): credentials, `X-Device-Fp`, `Retry-After`, niepusty `allow_origin`;
- ciasteczka: `same_site=none` bez `secure` = ostrzeżenie (przeglądarka odrzuci ciasteczko); `none` przy froncie
  w tej samej domenie co API = podpowiedź „lax wystarczy” (gdy da się ustalić origin frontu); info o domenie;
- trusted proxies (IP usera dla historii logowań i limitu prób);
- wersja bundla.

## Wymagania

- PHP `>=8.2`, Symfony `^6.4 || ^7.0` (framework-bundle, security-bundle, http-client, console)
- `cache.app` (zalecany Redis — snapshot userów, tokenVersion z webhooka, circuit breaker)
- Auth server z 2FA (API Core od 2026-10) — doctor sprawdza
- Opcjonalnie: `nelmio/cors-bundle`, gdy front działa pod innym originem niż API

## Instalacja ręczna (bez `auth-client:install`)

`security.yaml` — dokładnie to, co generuje install (`SecurityConfigurator::template()`):

```yaml
security:
    providers:
        auth_client_users:
            memory: ~
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        login:
            pattern: '^/api/(login|login/mfa|logout|token/refresh|token/invalidate|session/mfa|mfa/enrollment/request|auth-client/webhook/user-invalidated)$'
            stateless: true
            security: false
        api:
            pattern: ^/api
            stateless: true
            provider: auth_client_users
            custom_authenticators:
                - Musikhood\AuthClient\Security\ApiTokenAuthenticator
                - Musikhood\AuthClient\Security\JwtCookieAuthenticator
            entry_point: Musikhood\AuthClient\Security\JwtCookieAuthenticator
    access_control:
        - { path: '^/api/(login|login/mfa|logout|token/refresh|token/invalidate|session/mfa|mfa/enrollment/request|auth-client/webhook/user-invalidated)$', roles: PUBLIC_ACCESS }
        - { path: ^/api, roles: IS_AUTHENTICATED_FULLY }
```

Trasy: `config/routes/auth_client.yaml` z `resource: '@AuthClientBundle/Resources/config/routes.yaml'`.
CORS i trusted proxies — jak w tabeli `auth-client:install` wyżej.

## Opcjonalnie: lokalna kopia userów (encja + tabela)

Potrzebne tylko, gdy aplikacja chce trzymać userów u siebie (np. relacje w bazie,
wyszukiwanie po e-mailu w zapytaniach — jak PIM). Gdy kontener ma implementację
`PanelUserRepositoryInterface`, bundle używa jej zamiast trybu bezstanowego —
bez żadnej innej zmiany konfiguracji.

### Encja `User`

Paczka nigdy nie pisze do tabeli użytkowników — to robi konsument.
Zaimplementuj `Musikhood\AuthClient\Contract\PanelUserInterface`
(referencja: [`docs/example-entity.php`](docs/example-entity.php)):

```php
// src/Entity/User.php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Musikhood\AuthClient\Contract\PanelUserInterface;
use Ramsey\Uuid\UuidInterface;

#[ORM\Entity(repositoryClass: \App\Repository\UserRepository::class)]
#[ORM\Table(name: 'users')]
#[ORM\UniqueConstraint(name: 'uniq_users_email', columns: ['email'])]
class User implements PanelUserInterface
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private UuidInterface $id;

    #[ORM\Column(type: 'string', length: 180, unique: true)]
    private string $email;

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    private ?string $displayName = null;

    /** @var list<string> */
    #[ORM\Column(type: 'json')]
    private array $rolesForPanel = [];

    #[ORM\Column(type: 'boolean', options: ['default' => false])]
    private bool $disabled = false;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $lastSyncedAt;

    private function __construct() {}

    /** @param list<string> $rolesForPanel */
    public static function create(
        UuidInterface $id,
        string $email,
        ?string $displayName,
        array $rolesForPanel,
    ): self {
        $user = new self();
        $user->id = $id;
        $user->email = $email;
        $user->displayName = $displayName;
        $user->rolesForPanel = array_values($rolesForPanel);
        $user->disabled = false;
        $user->lastSyncedAt = new \DateTimeImmutable();
        return $user;
    }

    /** @param list<string> $rolesForPanel */
    public function syncFromClaims(string $email, ?string $displayName, array $rolesForPanel): void
    {
        $this->email = $email;
        $this->displayName = $displayName;
        $this->rolesForPanel = array_values($rolesForPanel);
        $this->lastSyncedAt = new \DateTimeImmutable();
    }

    public function markDisabled(bool $disabled): void { $this->disabled = $disabled; }
    public function getId(): UuidInterface { return $this->id; }
    public function getEmail(): string { return $this->email; }
    public function getDisplayName(): ?string { return $this->displayName; }
    /** @return list<string> */
    public function getRolesForPanel(): array { return $this->rolesForPanel; }
    public function isDisabled(): bool { return $this->disabled; }

    /** @return list<string> */
    public function getRoles(): array
    {
        $roles = ['ROLE_USER'];
        foreach ($this->rolesForPanel as $r) { $roles[] = 'ROLE_' . $r; }
        return array_values(array_unique($roles));
    }

    public function getUserIdentifier(): string { return $this->email; }
    public function eraseCredentials(): void {}
}
```

Jeśli używasz innej lokalizacji niż `src/Entity/` (np. DDD ze strukturą
`src/Domain/User/Entity/User.php`), umieść klasę gdziekolwiek — paczka
patrzy tylko na kontrakt `PanelUserInterface`.

### `UserRepository`

Zaimplementuj `Musikhood\AuthClient\Contract\PanelUserRepositoryInterface`
i powiąż go z interfejsem przez atrybut `#[AsAlias]`. Dzięki temu **nie
musisz nic dopisywać do `services.yaml`** — Symfony sam podepnie repo pod
interfejs.

Referencja: [`docs/example-repository.php`](docs/example-repository.php).

```php
// src/Repository/UserRepository.php
namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Musikhood\AuthClient\Contract\PanelUserInterface;
use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Ramsey\Uuid\UuidInterface;
use Symfony\Component\DependencyInjection\Attribute\AsAlias;

/** @extends ServiceEntityRepository<User> */
#[AsAlias(id: PanelUserRepositoryInterface::class)]
class UserRepository extends ServiceEntityRepository implements PanelUserRepositoryInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function findById(UuidInterface $id): ?PanelUserInterface
    {
        return $this->find($id);
    }

    public function findByEmail(string $email): ?PanelUserInterface
    {
        return $this->findOneBy(['email' => $email]);
    }

    public function save(PanelUserInterface $user): void
    {
        $this->getEntityManager()->persist($user);
    }

    public function flush(): void
    {
        $this->getEntityManager()->flush();
    }

    public function createFromClaims(
        UuidInterface $id,
        string $email,
        ?string $displayName,
        array $rolesForPanel,
    ): PanelUserInterface {
        return User::create($id, $email, $displayName, $rolesForPanel);
    }
}
```

Atrybut `#[AsAlias]` wymaga Symfony 6.1+. Jeśli z jakiegoś powodu wolisz
mapowanie w YAML-u, zamiast atrybutu dodaj do `config/services.yaml`:

```yaml
services:
    Musikhood\AuthClient\Contract\PanelUserRepositoryInterface:
        alias: App\Repository\UserRepository
```

Bez aliasu bundle używa trybu bezstanowego (od 0.8 — wcześniej rzucał wyjątek).

### Tabela w bazie

Albo skopiuj [`docs/example-migration.sql`](docs/example-migration.sql)
prosto do swojego narzędzia migracji, albo wygeneruj migrację z encji:

```bash
php bin/console doctrine:migrations:diff
php bin/console doctrine:migrations:migrate
```

Tabela potrzebuje kolumn: `id` (UUID), `email` (unique), `display_name`,
`roles_for_panel` (JSON), `disabled` (bool), `last_synced_at`. Pełny
mapping w `docs/example-entity.php`.

## Synchronizacja z auth serverem

Auth server jest jedynym źródłem prawdy dla ról, displayName i flagi
`disabled`. Kopia użytkownika po stronie panelu — w trybie bezstanowym snapshot
w `cache.app`, w trybie z lokalną tabelą wiersz w bazie — jest aktualizowana
w dwóch momentach:

1. **Pierwszy kontakt z userem (bootstrap)** — gdy authenticator widzi
   zalogowanego usera, którego jeszcze nie ma w lokalnej tabeli, paczka
   tworzy kopię z claimów świeżego JWT (email, displayName,
   role per-panel). To jednorazowe — przy każdym kolejnym requeście
   tego usera authenticator NIE rusza już lokalnej kopii.
2. **Co ~30s na żądanie zalogowanego usera** — `AuthValidationListener`
   woła introspekcję na auth serverze (`POST /api/auth/backend/introspect`) i synchronizuje pełen payload
   (email, displayName, role per-panel, flaga `disabled`). To jest jedyna
   ścieżka aktualizacji istniejącej kopii. Krok pomijany jeśli wynik
   z poprzedniego wywołania jeszcze leży w cache
   (`validation_cache_ttl`, domyślnie 30s).

W szczególności **paczka nie używa lokalnej flagi `isDisabled()` do
podejmowania decyzji o autoryzacji**. Gating disabled userów leci
wyłącznie przez `/me` — co znaczy że:

- Po **zablokowaniu** konta w panelu admin auth servera użytkownik
  zostanie wylogowany w czasie max. `validation_cache_ttl` sekund.
- Po **odblokowaniu** konta użytkownik znowu działa bez ponownego
  logowania (jeśli JWT jest jeszcze ważny — w innym przypadku front
  interceptor zrobi `/api/token/refresh` i auth server wystawi nowy).
- Po zmianie ról / displayName w panelu admin nowe wartości pojawią się
  w lokalnej kopii w czasie max. `validation_cache_ttl` sekund. Auth
  server NIE podbija `tokenVersion` przy tych zmianach — istniejące JWT
  zostają ważne, propagacja idzie przez `/me`.

Lokalne pole `disabled` (w encji konsumenta albo w snapshot'cie trybu
bezstanowego) służy tylko do wyświetlenia. Aktualizowane automatycznie przez
`syncFromMe()`.

Tryb bezstanowy przechowuje snapshot w `cache.app` (TTL 24 h) — utrata cache
jest nieszkodliwa (user zostaje odtworzony z JWT, a następna introspekcja go
zsynchronizuje). Zalecany Redis, żeby workery widziały ten sam stan.

## Webhook inwalidacji (0s revocation)

Od wersji `0.3.0` paczka nasłuchuje webhooków od auth servera i skraca czas
rewokacji sesji z ~30s (poll `/me` opisany wyżej) do setek milisekund.

**Jak to działa.** Po inwalidacji usera (zablokowanie konta, zmiana hasła,
odebranie dostępu do panelu) auth server podbija `tokenVersion` i pushuje
podpisany webhook na endpoint paczki
`POST /api/auth-client/webhook/user-invalidated`. Paczka weryfikuje podpis
(`WebhookJwtValidator`, ten sam JWKS co user JWT), zapisuje nową `tokenVersion`
w cache (`UserTokenVersionStore`) i kasuje cache walidacji usera. Przy
najbliższym requeście tego usera `JwtCookieAuthenticator` porównuje `ver`
z jego JWT z zapisaną wartością i odrzuca stary token (401) bez czekania na
poll `/me`.

**Co musisz zrobić.**

1. Ścieżka webhooka musi być publiczna — `auth-client:install` umieszcza ją
   w firewallu `login` (lista tras publicznych: `Musikhood\AuthClient\Routing\PublicRoutes`).
   Webhook autoryzuje się sam podpisem JWT auth servera — to model jak
   weryfikacja podpisu webhooków Stripe/GitHub, nie dziura w security.
2. W panelu admin auth servera ustaw pole „Webhook URL" dla swojego panelu na
   bazowy URL backendu mikroserwisu (np. `https://pim.vitkac.com`). Auth server
   sam dokleja ścieżkę `/api/auth-client/webhook/user-invalidated`.
3. Upewnij się, że `cache.app` jest skonfigurowane (Redis zalecany — stan musi
   być współdzielony między procesami workerów i przeżyć restart).

**Nie musisz nic zmieniać w swojej encji.** `tokenVersion` żyje w cache PSR,
nie w kolumnie DB — webhook może przyjść nawet dla usera, którego mikroserwis
jeszcze nie zna lokalnie. Reset cache (flush Redisa) jest nieszkodliwy: brak
wpisu = pass, a poll `/me` dogoni inwalidację w ~30s (fallback).

**Monolog tip.** Jeśli używasz `fingers_crossed` z `action_level: error`
(typowy prod default Symfony), logi `webhook.received` (poziom `info`) będą
buforowane i tracone, gdy webhook kończy się 200 OK — bufor jest zrzucany
tylko gdy w tym samym requeście wystąpi `error`. Żeby widzieć je w
`kubectl logs`, dodaj osobny handler/channel ze `stream` do `php://stderr`
na poziomie `info`.

## Kontrakt z front-endem

Front nigdy nie widzi JWT. Wymaga:

- `axios.defaults.withCredentials = true` (lub równowartość `fetch` z
  `credentials: 'include'`)
- na `401` z dowolnego `/api/*`: `POST /api/token/refresh`, potem retry
- na `401` z `/api/token/refresh`: czyść lokalny stan UI, redirect do logowania
- na **`403`** z dowolnego `/api/*` (brak dostępu do tego panelu, sesja ŻYJE):
  **NIE** refreshuj, **NIE** czyść ciasteczek, **NIE** broadcastuj wylogowania —
  pokaż ekran „brak dostępu" / login. Ciasteczka SSO zostają ważne na panelach,
  do których user MA dostęp. Paczka `@musikhood-dev/auth-client` klasyfikuje to
  jako `PanelAccessDeniedError` automatycznie.

Kontrakt 401 vs 403: **401 = sesja martwa** (globalne wylogowanie po nieudanym
refreshu), **403 = brak dostępu do panelu** (sesja żyje, bez czyszczenia).

To ten sam kontrakt co przy gadaniu wprost z auth serverem, więc istniejący
front przesiada się na inny backend bez zmian.

## Pełna konfiguracja

Plik `config/packages/auth_client.yaml` jest **opcjonalny** — wszystkie klucze
mają domyślne wartości (dane panelu z env). Recipe wgrywa tylko cztery linie
z env, żeby było widać, skąd biorą się dane. Pełny dump:
`bin/console config:dump-reference auth_client`.

```yaml
auth_client:
    base_url:      '%env(AUTH_BASE_URL)%'      # domyślnie env AUTH_BASE_URL, bez niego https://editor-v3-backend.vitkac.com
    panel_id:      '%env(AUTH_PANEL_ID)%'      # domyślnie env AUTH_PANEL_ID (API-token gating; NIE bramkuje JWT)
    client_id:     '%env(AUTH_CLIENT_ID)%'     # domyślnie env AUTH_CLIENT_ID
    client_secret: '%env(AUTH_CLIENT_SECRET)%' # domyślnie env AUTH_CLIENT_SECRET

    jwks_cache_ttl: 3600         # TTL cache dokumentu JWKS (sekundy)
    validation_cache_ttl: 30     # TTL cache introspekcji per user (sekundy)

    cookie:
        access_name: BEARER
        refresh_name: refresh_token
        path: /
        domain: '%env(default::AUTH_COOKIE_DOMAIN)%'  # pusty = host-only; np. .vitkac.com gdy front i API są na różnych subdomenach
        secure: true
        http_only: true
        same_site: lax           # lax | strict | none — none tylko gdy front i API w różnych domenach (wymaga secure)
        # TTL ciasteczek nie jest konfigurowalne — paczka zna typowe wartości
        # auth servera (BEARER 15 min, refresh_token 30 dni). Jeśli auth server
        # ma inne TTL, podbumpuj wersję paczki.

    device_binding:
        mode: observe            # off | observe | enforce — porównanie claimu fph z X-Device-Fp
    circuit_breaker:
        failure_threshold: 3     # ile kolejnych błędów introspekcji otwiera breaker
        open_seconds: 60         # ile sekund breaker jest otwarty

    http:
        timeout: 5.0
        max_duration: 10.0

    api_token:
        enabled: true            # czy ApiTokenAuthenticator jest aktywny
        header: X-Api-Token      # nagłówek niosący raw token
        cache_ttl: 0             # 0 = bez cache → natychmiastowa rewokacja
```

`same_site` domyślnie `lax` — wystarcza, gdy front i API są w tej samej domenie rejestrowalnej (SameSite liczy
się po „site”, nie po hoście): `pim.vitkac.com` + `pim-api.vitkac.com`, `localhost` na różnych portach.
`none` ustaw tylko, gdy front i API są w **różnych domenach** (np. `panel.example.com` ↔ `api.vitkac.com`) —
wymaga `secure: true` (HTTPS) i osłabia ochronę przed CSRF.

## API token (autoryzacja maszynowa)

Drugi sposób autoryzacji obok ciasteczek — dla klientów server-to-server, które
nie mają sesji przeglądarkowej. Klient wysyła per-user-per-panel token w
nagłówku `X-Api-Token` (format `mhpat_…`), bez logowania, ciasteczek ani
refreshu.

```
GET /api/v1/products
X-Api-Token: mhpat_AbCd…
```

`ApiTokenAuthenticator` reaguje tylko gdy nagłówek jest obecny, więc współistnieje
z `JwtCookieAuthenticator` w tym samym firewallu — bez nagłówka stary cookie flow
działa bez zmian. Token jest weryfikowany live przez introspekcję na auth serverze
(`POST /api/auth/backend/api-token/verify`) — paczka nie trzyma kopii, więc revoke
po stronie auth servera = natychmiastowa rewokacja (następny request → 401). Gdy
auth server jest niedostępny, authenticator robi **fail-closed** (401).

Role pochodzą z `panelRoles` introspekcji (z prefiksem `ROLE_`), tak samo jak przy
JWT — istniejące `#[IsGranted('ROLE_PUBLISH')]` działają bez zmian. Token jest
generowany / regenerowany / usuwany wyłącznie przez admina w panelu auth servera
(„niezmienny" = brak edycji wartości; zmiana = regeneracja, stary natychmiast
martwy).

## 2FA (TOTP) i wiązanie sesji z urządzeniem (>= 0.7)

Wymaga auth servera z wydaniem 2FA. Front: `@musikhood-dev/auth-client >= 2.2`.
Panel z polityką 2FA `off` (domyślnie) i user bez 2FA = zachowanie bajt w bajt jak w 0.6.

- **`/api/login`** przepuszcza 401 `{code: "mfa_required", mfa_token, methods}` (BEZ ciasteczek) i 403
  `{code: "mfa_enrollment_required", enrollment_url}`; zwykłe złe dane = 401 `"Nieprawidłowy login lub hasło."`
  (+ `code: invalid_credentials`). 429 `too_many_attempts` + `Retry-After`.
- **Per request** (`AuthValidationListener`): introspekcja zwraca 403 `mfa_step_up` / `mfa_enrollment_required`,
  gdy sesja nie spełnia polityki 2FA panelu — bundle odpowiada 403 z tym samym `code` (bez czyszczenia ciasteczek,
  wynik nie jest cache'owany). 403 `mfa_enrollment_required` z bramki NIE zawiera linku — front prosi o hasło i woła
  `/api/mfa/enrollment/request` (link jest tylko w odpowiedzi `/api/login`).
- **Dane end-usera dla auth servera**: przy `/api/auth/backend/*` bundle wysyła `X-Client-Ip`
  (`Request::getClientIp()` — skonfiguruj `framework.trusted_proxies`!), `X-Client-User-Agent`, `X-Device-Fp` oraz
  `device` z body przeglądarki. Auth server ufa im wyłącznie po poprawnym HTTP Basic panelu. Bez nich (stary bundle)
  historia logowań widzi IP serwera konsumenta, a auth server pomija dla takich wywołań limit prób per IP (zostaje
  limit IP+email) — inaczej userzy jednego serwisu blokowaliby się nawzajem.
- **Fingerprint**: `JwtCookieAuthenticator` porównuje claim `fph` z nagłówkiem `X-Device-Fp` wg
  `auth_client.device_binding.mode`: `off` | `observe` (default, tylko log) | `enforce` (401 `device_mismatch_recheck`
  — także przy braku nagłówka na tokenie z `fph` → front robi refresh; auth server robi pełny scoring). Refresh odrzucony z `device_mismatch` → 401 + czyszczenie ciasteczek.
- **CORS** backendu konsumenta musi dopuszczać nagłówek `X-Device-Fp` (`allow_headers`) i wystawiać `Retry-After`
  (`expose_headers`) — auth-client 2.2 wysyła `X-Device-Fp` na każdym requeście. Od 0.8 robi to `auth-client:install`.
- **Firewall**: trasy 2FA są w publicznym firewallu `login` — od 0.8 robi to `auth-client:install`, a
  `auth-client:doctor` sprawdza pokrycie na żywej konfiguracji.
- **Polityka 2FA i device binding** ustawia się wyłącznie w auth-panelu (panel: `mfa_policy`, `device_binding`).
  `device_binding.mode` w bundlu zostaw `observe`.
- Nowe wyjątki `AuthBackendClient` (podklasy dotychczasowych — stary kod łapiący `AuthBackendUnauthorizedException` /
  `AuthBackendForbiddenException` działa fail-closed): `AuthBackendMfaRequiredException`,
  `AuthBackendMfaEnrollmentRequiredException`, `AuthBackendMfaStepUpException`, `AuthBackendMfaInvalidCodeException`,
  `AuthBackendMfaTokenExpiredException`, `AuthBackendDeviceMismatchException`, `AuthBackendMfaAlreadyEnabledException`,
  `AuthBackendTooManyAttemptsException`. Nowe metody: `loginMfa()`, `sessionMfa()`, `requestMfaEnrollment()`;
  `login()` / `refresh()` przyjmują opcjonalne `$device`.

## Endpointy wystawiane przez paczkę

| Metoda | Ścieżka | Opis |
|---|---|---|
| `POST` | `/api/login` | Wymienia `{username, password}` na ciasteczka `BEARER` + `refresh_token`. |
| `POST` | `/api/logout` (alias `/api/token/invalidate`) | Czyści ciasteczka, unieważnia refresh token w auth serverze. |
| `POST` | `/api/token/refresh` | Generuje nową parę ciasteczek z refresh tokena. |
| `GET` | `/api/v1/user/me` | Zwraca dane zalogowanego użytkownika (`id`, `email`, `displayName`, `roles`, `disabled`). Czyta z lokalnej kopii — nie wymaga round-tripa do auth servera. |
| `POST` | `/api/login/mfa` | (0.7) Drugi krok logowania 2FA: `{mfa_token, code \| recovery_code, remember_device?, device?}` → ciasteczka jak `/api/login`. Publiczny. |
| `POST` | `/api/session/mfa` | (0.7) Step-up sesji po 403 `mfa_step_up`: `{code \| recovery_code, remember_device?, device?}` + ciasteczko `refresh_token` → nowe ciasteczka. Publiczny (autoryzacja refresh tokenem). |
| `POST` | `/api/mfa/enrollment/request` | (0.7) Link do konfiguracji 2FA dla zalogowanego usera: `{password}` (wymagane aktualne hasło) + ciasteczko `refresh_token` → `{enrollment_url}`; 401 `invalid_credentials`, 409 `mfa_already_enabled`, 429. Publiczny (refresh token + hasło). |
| `POST` | `/api/auth-client/webhook/user-invalidated` | Webhook inwalidacji usera (0s revocation). Autoryzacja podpisem JWT auth servera (nie user auth — wymaga `PUBLIC_ACCESS` w `access_control`). Patrz „Webhook inwalidacji". |

## Licencja

MIT — patrz [LICENSE](LICENSE).
