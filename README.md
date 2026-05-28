# auth-client-bundle

Symfony bundle dla mikroserwisów, które delegują uwierzytelnianie do
zewnętrznego auth servera (editor_v3) i wystawiają front-endowi spójny
kontrakt oparty na ciasteczkach HttpOnly.

Bundle obsługuje całą warstwę HTTP — endpointy `/api/login`, `/api/logout`,
`/api/token/refresh`, `/api/v1/user/me` — walidację JWT/JWKS, kontrakt
ciasteczek (`BEARER` + `refresh_token`, oba HttpOnly), lokalną kopię
użytkownika z lazy upsert oraz listener z circuit breakerem, który co 30 s
weryfikuje sesję w auth serverze.

Front nigdy nie widzi JWT. Używa `withCredentials: true` plus interceptora
axiosa, który na `401` woła `/api/token/refresh`. Front napisany przeciw
samemu auth serverowi działa bez zmian z dowolnym mikroserwisem
korzystającym z tej paczki.

## Wymagania

- PHP `>=8.2`
- Symfony `^6.4 || ^7.0` (security-bundle, framework-bundle, http-client)
- ORM po stronie konsumenta (zalecany Doctrine) — paczka dostarcza tylko
  interfejsy (`PanelUserInterface`, `PanelUserRepositoryInterface`); konkretną
  encję i repozytorium tworzy konsument.

## Instalacja

### 1. Dodaj endpoint Symfony Flex

Bundle dostarcza recipe Symfony Flex, które konfiguruje `bundles.php`,
`config/packages/auth_client.yaml`, import tras i zmienne środowiskowe.
Recipe siedzi w
[musikhood/symfony-recipes](https://github.com/musikhood/symfony-recipes).

Dodaj endpoint do `composer.json` **w aplikacji konsumenta** (jednorazowo):

```json
{
    "extra": {
        "symfony": {
            "endpoint": [
                "https://api.github.com/repos/musikhood/symfony-recipes/contents/index.json",
                "flex://defaults"
            ]
        }
    }
}
```

Zostaw `flex://defaults` po swoim endpoincie — bez tego nie będą działać
oficjalne recipes Symfony (Doctrine, Mailer itd.).

### 2. Zainstaluj paczkę

```bash
composer require musikhood/auth-client-bundle:^0.1
```

Flex zrobi automatycznie:

- zarejestruje `Musikhood\AuthClient\AuthClientBundle` w `config/bundles.php`
- utworzy `config/packages/auth_client.yaml` z szablonem na zmienne środowiskowe
- utworzy `config/routes/auth_client.yaml` importujący trasy paczki
- doda klucze `AUTH_*` do `.env`
- wyświetli listę kroków, które musisz dokończyć ręcznie (sekcja 3 niżej)

Jeśli `composer require` nie pokaże komunikatu post-install, prawdopodobnie:
- Flex nie jest zainstalowany w konsumencie (`composer require symfony/flex`)
- brakuje konfiguracji endpointu z kroku 1
- paczka była już zainstalowana wcześniej — zrób `composer remove
  musikhood/auth-client-bundle && composer clear-cache` i powtórz `require`

### 3. Kroki, które musisz wykonać ręcznie

Recipe robi tylko to, co bezpiecznie da się zautomatyzować. Pięć rzeczy
wymaga jeszcze Twojej ręki — wszystkie dotykają miejsc specyficznych dla
projektu, których recipe nie może zgadnąć.

#### 3.1. Ustaw zmienne środowiskowe

W `.env.local` (albo Twoim secrets manager):

```dotenv
AUTH_BASE_URL=https://auth.twoja-domena.com
AUTH_PANEL_ID=01234567-89ab-cdef-0123-456789abcdef
AUTH_CLIENT_ID=<z panelu admin auth servera>
AUTH_CLIENT_SECRET=<z panelu admin auth servera>
AUTH_COOKIE_SECURE=1
```

`AUTH_COOKIE_SECURE` ustaw na `1` w produkcji (HTTPS), `0` tylko dla
lokalnego deva po HTTP.

#### 3.2. Stwórz encję `User`

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

#### 3.3. Stwórz `UserRepository`

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

Paczka rozwiązuje `PanelUserRepositoryInterface` z kontenera DI — bez
jednego z tych dwóch wariantów authenticator i `MeController` wywalą się
przy starcie z błędem "Cannot autowire".

#### 3.4. Skonfiguruj security

Recipe **nie modyfikuje** `config/packages/security.yaml`, bo większość
projektów ma już własny firewall i auto-merge byłby ryzykowny. Skopiuj ten
fragment ręcznie:

```yaml
# config/packages/security.yaml
security:
    providers:
        # Authenticator zwraca User-a wprost — Symfony nie ma skąd go
        # przeładować, więc in_memory provider jest poprawny.
        in_memory:
            memory: ~

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        login:
            # Login, logout i refresh muszą być publiczne — authenticator
            # nie może działać na /api/token/refresh, bo access_token jest
            # wtedy już nieważny.
            pattern: ^/api/(login|logout|token/(refresh|invalidate))$
            stateless: true
            security: false

        api:
            pattern: ^/api
            stateless: true
            custom_authenticators:
                - Musikhood\AuthClient\Security\JwtCookieAuthenticator
            entry_point: Musikhood\AuthClient\Security\JwtCookieAuthenticator

    access_control:
        - { path: ^/api/(login|logout|token/(refresh|invalidate)), roles: PUBLIC_ACCESS }
        # Webhook inwalidacji usera (0s revocation) — własna autoryzacja przez
        # podpis JWT auth servera, NIE user auth. MUSI być przed catch-all ^/api.
        - { path: ^/api/auth-client/webhook/, roles: PUBLIC_ACCESS }
        - { path: ^/api, roles: IS_AUTHENTICATED_FULLY }

    # Opcjonalnie: zdefiniuj hierarchię ról. Paczka nie narzuca żadnych
    # konkretnych ról — `panel_roles` z JWT są wystawiane wprost z
    # prefiksem ROLE_.
    role_hierarchy:
        ROLE_ADMIN: [ROLE_USER]
```

#### 3.5. Stwórz tabelę w bazie

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
`disabled`. Lokalna kopia użytkownika w mikroserwisie jest aktualizowana
w dwóch momentach:

1. **Pierwszy kontakt z userem (bootstrap)** — gdy authenticator widzi
   zalogowanego usera, którego jeszcze nie ma w lokalnej tabeli, paczka
   tworzy lokalną kopię z claimów świeżego JWT (email, displayName,
   role per-panel). To jednorazowe — przy każdym kolejnym requeście
   tego usera authenticator NIE rusza już lokalnej kopii.
2. **Co ~30s na żądanie zalogowanego usera** — `AuthValidationListener`
   woła `/api/v1/user/me` na auth serverze i synchronizuje pełen payload
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

Lokalne pole `disabled` w encji konsumenta służy tylko do wyświetlenia
(np. w panelu zarządzania userami w mikroserwisie). Aktualizowane
automatycznie przez `syncFromMe()`.

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

1. Dodaj `PUBLIC_ACCESS` dla ścieżki webhooka w `security.yaml` (patrz krok
   „Skonfiguruj security" powyżej). Webhook autoryzuje się sam podpisem JWT
   auth servera — to model jak weryfikacja podpisu webhooków Stripe/GitHub,
   nie dziura w security.
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

Front nigdy nie widzi JWT. Wymaga trzech rzeczy:

- `axios.defaults.withCredentials = true` (lub równowartość `fetch` z
  `credentials: 'include'`)
- na `401` z dowolnego `/api/*`: `POST /api/token/refresh`, potem retry
- na `401` z `/api/token/refresh`: czyść lokalny stan UI, redirect do logowania

To dokładnie ten sam kontrakt co przy gadaniu wprost z auth serverem,
więc istniejący front przesiada się na inny backend bez zmian.

## Pełna konfiguracja

Wszystkie klucze z domyślnymi wartościami — ustawiasz je w
`config/packages/auth_client.yaml`. Recipe wgrywa tylko klucze wymagane
(cztery `AUTH_*` env-y plus `cookie.secure`); reszta poniżej ma sensowne
defaulty.

```yaml
auth_client:
    base_url:      '%env(AUTH_BASE_URL)%'      # wymagane
    panel_id:      '%env(AUTH_PANEL_ID)%'      # wymagane
    client_id:     '%env(AUTH_CLIENT_ID)%'     # wymagane
    client_secret: '%env(AUTH_CLIENT_SECRET)%' # wymagane

    jwks_cache_ttl: 3600         # TTL cache dokumentu JWKS (sekundy)
    validation_cache_ttl: 30     # TTL cache introspekcji /me per user (sekundy)

    cookie:
        access_name: BEARER
        refresh_name: refresh_token
        path: /
        secure: '%env(bool:default::AUTH_COOKIE_SECURE)%'
        http_only: true
        same_site: lax           # lax | strict | none
        # TTL ciasteczek nie jest konfigurowalne — paczka zna typowe wartości
        # auth servera (BEARER 15 min, refresh_token 30 dni). Jeśli auth server
        # ma inne TTL, podbumpuj wersję paczki.

    circuit_breaker:
        failure_threshold: 3     # ile kolejnych błędów /me otwiera breaker
        open_seconds: 60         # ile sekund breaker jest otwarty

    http:
        timeout: 5.0
        max_duration: 10.0
```

## Endpointy wystawiane przez paczkę

| Metoda | Ścieżka | Opis |
|---|---|---|
| `POST` | `/api/login` | Wymienia `{username, password}` na ciasteczka `BEARER` + `refresh_token`. |
| `POST` | `/api/logout` (alias `/api/token/invalidate`) | Czyści ciasteczka, unieważnia refresh token w auth serverze. |
| `POST` | `/api/token/refresh` | Generuje nową parę ciasteczek z refresh tokena. |
| `GET` | `/api/v1/user/me` | Zwraca dane zalogowanego użytkownika (`id`, `email`, `displayName`, `roles`, `disabled`). Czyta z lokalnej kopii — nie wymaga round-tripa do auth servera. |
| `POST` | `/api/auth-client/webhook/user-invalidated` | Webhook inwalidacji usera (0s revocation). Autoryzacja podpisem JWT auth servera (nie user auth — wymaga `PUBLIC_ACCESS` w `access_control`). Patrz „Webhook inwalidacji". |

## Licencja

MIT — patrz [LICENSE](LICENSE).
