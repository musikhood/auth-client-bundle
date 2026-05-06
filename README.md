# auth-client-bundle

Symfony bundle providing cookie-based authentication for microservices that
delegate identity to an external editor_v3 auth server.

The bundle owns the full HTTP-facing flow — `/api/login`, `/api/logout`,
`/api/token/refresh`, `/api/v1/user/me` — JWT/JWKS validation, the cookie
contract (`BEARER` + `refresh_token`, both HttpOnly), the local user mirror
syncer and a circuit-breaker'd introspection listener that revalidates the
session every 30 s against the auth server.

The frontend never sees the JWT. It just uses `withCredentials: true` and an
axios interceptor that retries on `401` via `/api/token/refresh`. A frontend
written for the auth server itself works unmodified against any microservice
using this bundle.

## Requirements

- PHP `>=8.2`
- Symfony `^6.4 || ^7.0` (security-bundle, framework-bundle, http-client)
- An ORM (Doctrine recommended) on the consuming side — the bundle ships only
  interfaces (`PanelUserInterface`, `PanelUserRepositoryInterface`); the
  actual entity and repository live in the consumer.

## Installation

### 1. Configure the Flex endpoint

The bundle ships a Symfony Flex recipe that wires up `bundles.php`,
`config/packages/auth_client.yaml`, the routes import, and the env vars.
The recipe is hosted at
[musikhood/symfony-recipes](https://github.com/musikhood/symfony-recipes).

Add the endpoint to the **consuming app's** `composer.json` (one-time
setup):

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

Keep `flex://defaults` after your endpoint — it keeps the official Symfony
recipes (Doctrine, Mailer, etc.) working.

### 2. Add the package as a Composer repository

Until the bundle lands on Packagist, declare the GitHub repo as a VCS
repository in the consumer's `composer.json`:

```json
{
    "repositories": [
        { "type": "vcs", "url": "https://github.com/musikhood/auth-client-bundle.git" }
    ]
}
```

### 3. Install

```bash
composer require musikhood/auth-client-bundle:^0.1
```

Flex will:

- register `Musikhood\AuthClient\AuthClientBundle` in `config/bundles.php`
- create `config/packages/auth_client.yaml` with the env-var template
- create `config/routes/auth_client.yaml` importing the bundle's routes
- append the `AUTH_*` env keys to `.env`
- print a list of the manual steps still required (Section 4 below)

If you are seeing a `composer require` hang on "Resolving dependencies"
without the recipe running, either Flex is not installed in the consumer
(`composer require symfony/flex`) or the endpoint config from Step 1 is
missing.

### 4. Manual steps still required

The recipe takes care of everything that is **safe** to do automatically.
Five things still need a human — they all touch consumer-specific code paths
that the recipe cannot guess:

#### 4.1. Set the env vars

In `.env.local` (or your secrets manager):

```dotenv
AUTH_BASE_URL=https://auth.your-domain.com
AUTH_PANEL_ID=01234567-89ab-cdef-0123-456789abcdef
AUTH_CLIENT_ID=<from auth-server admin panel>
AUTH_CLIENT_SECRET=<from auth-server admin panel>
AUTH_COOKIE_SECURE=1
```

`AUTH_COOKIE_SECURE` should be `1` in production (HTTPS) and `0` only for
local HTTP dev.

#### 4.2. Create the User entity

The bundle never writes a user table — your app does. Implement
`Musikhood\AuthClient\Contract\PanelUserInterface` with a Doctrine entity
(reference: [`docs/example-entity.php`](docs/example-entity.php)):

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

If your project uses a non-default location for entities (e.g. DDD with
`src/Domain/User/Entity/User.php`), put the class wherever you like — only
the `PanelUserInterface` contract matters to the bundle.

#### 4.3. Create the User repository

Implement `Musikhood\AuthClient\Contract\PanelUserRepositoryInterface`
(reference: [`docs/example-repository.php`](docs/example-repository.php)):

```php
// src/Repository/UserRepository.php
namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Musikhood\AuthClient\Contract\PanelUserInterface;
use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Ramsey\Uuid\UuidInterface;

/** @extends ServiceEntityRepository<User> */
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

Then alias the interface to your concrete repository in `config/services.yaml`:

```yaml
services:
    Musikhood\AuthClient\Contract\PanelUserRepositoryInterface:
        alias: App\Repository\UserRepository
```

The bundle resolves `PanelUserRepositoryInterface` from the container —
without this alias, the authenticator and `MeController` will fail with
"Cannot autowire" at compile time.

#### 4.4. Configure security

The recipe does **not** touch `config/packages/security.yaml` because most
projects already have a custom firewall config and merging would be unsafe.
Add this snippet by hand:

```yaml
# config/packages/security.yaml
security:
    providers:
        # The authenticator returns the User directly — there is no source
        # for Symfony to reload from, so the in_memory provider is correct.
        in_memory:
            memory: ~

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        login:
            # Login, logout and refresh must be public — the authenticator
            # cannot run on /api/token/refresh because the access_token is
            # invalid by the time the request arrives there.
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
        - { path: ^/api, roles: IS_AUTHENTICATED_FULLY }

    # Optional: define your role hierarchy here. The bundle does not
    # prescribe any roles — `panel_roles` from the JWT are exposed verbatim
    # with a ROLE_ prefix.
    role_hierarchy:
        ROLE_ADMIN: [ROLE_USER]
```

#### 4.5. Create the database table

Either copy [`docs/example-migration.sql`](docs/example-migration.sql)
straight into your migration tool, or generate one from the entity:

```bash
php bin/console doctrine:migrations:diff
php bin/console doctrine:migrations:migrate
```

The schema needs an `id` (UUID), `email` (unique), `display_name`,
`roles_for_panel` (JSON), `disabled` (bool), `last_synced_at`. The exact
mapping is in `docs/example-entity.php`.

## Frontend contract

The frontend never sees the JWT. It needs three things:

- `axios.defaults.withCredentials = true` (or the equivalent `fetch` option)
- on `401` from any `/api/*` call: `POST /api/token/refresh`, then retry
- on `401` from `/api/token/refresh`: clear local UI state, redirect to login

This contract is identical to talking to the auth server directly, so an
existing frontend can switch backends without changes.

## Configuration reference

All keys with defaults — set in `config/packages/auth_client.yaml`. The
recipe ships only the required keys (the four `AUTH_*` env vars + cookie
secure); everything below has a sensible default.

```yaml
auth_client:
    base_url:      '%env(AUTH_BASE_URL)%'      # required
    panel_id:      '%env(AUTH_PANEL_ID)%'      # required
    client_id:     '%env(AUTH_CLIENT_ID)%'     # required
    client_secret: '%env(AUTH_CLIENT_SECRET)%' # required

    jwks_cache_ttl: 3600         # JWKS document cache TTL (seconds)
    validation_cache_ttl: 30     # /me introspection cache per user (seconds)

    cookie:
        access_name: BEARER
        refresh_name: refresh_token
        path: /
        secure: '%env(bool:default::AUTH_COOKIE_SECURE)%'
        http_only: true
        same_site: lax           # lax | strict | none
        lifetime: 2592000        # 30 days — should match refresh_token TTL upstream

    circuit_breaker:
        failure_threshold: 3     # consecutive /me failures before opening
        open_seconds: 60         # how long the breaker stays open

    http:
        timeout: 5.0
        max_duration: 10.0
```

## Endpoints exposed by the bundle

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/login` | Exchange `{username, password}` for `BEARER` + `refresh_token` cookies. |
| `POST` | `/api/logout` (alias `/api/token/invalidate`) | Clear cookies, invalidate refresh token upstream. |
| `POST` | `/api/token/refresh` | Mint a fresh cookie pair from the refresh token. |
| `GET` | `/api/v1/user/me` | Return the authenticated user (id, email, roles, disabled). |

## License

MIT — see [LICENSE](LICENSE).
