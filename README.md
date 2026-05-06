# auth-client-bundle

Symfony bundle providing cookie-based authentication for microservices that
delegate identity to an external editor_v3 auth server.

The bundle owns the full HTTP-facing flow: `/api/login`, `/api/logout`,
`/api/token/refresh`, `/api/v1/user/me`, JWT/JWKS validation, the cookie
contract (`BEARER` + `refresh_token`, both HttpOnly), the local user mirror
syncer and a circuit-breaker'd introspection listener that revalidates the
session every 30s against the auth server.

The frontend never sees the JWT — it only uses `withCredentials: true` and an
axios interceptor that retries on `401` via `/api/token/refresh`. This means a
front written for the auth server itself works unmodified against any
microservice using this bundle.

## Requirements

- PHP `>=8.2`
- Symfony `^6.4 || ^7.0` (security-bundle, framework-bundle, http-client)
- An ORM (Doctrine recommended) on the consuming side — the bundle only
  provides interfaces (`PanelUserInterface`, `PanelUserRepositoryInterface`),
  the actual entity and repository live in the consumer.

## Installation

Until the package lands on Packagist, add the VCS repository to your
consumer's `composer.json`:

```json
{
    "repositories": [
        { "type": "vcs", "url": "https://github.com/musikhood/auth-client-bundle.git" }
    ],
    "require": {
        "musikhood/auth-client-bundle": "^0.1"
    }
}
```

Then:

```bash
composer require musikhood/auth-client-bundle
```

Register the bundle in `config/bundles.php`:

```php
return [
    // ...
    Musikhood\AuthClient\AuthClientBundle::class => ['all' => true],
];
```

## Configuration

Create `config/packages/auth_client.yaml`:

```yaml
auth_client:
    base_url:      '%env(AUTH_BASE_URL)%'
    panel_id:      '%env(AUTH_PANEL_ID)%'
    client_id:     '%env(AUTH_CLIENT_ID)%'
    client_secret: '%env(AUTH_CLIENT_SECRET)%'

    # All of these have sensible defaults — set only if you need to override.
    jwks_cache_ttl: 3600
    validation_cache_ttl: 30
    cookie:
        access_name: BEARER
        refresh_name: refresh_token
        path: /
        secure: '%env(bool:default::AUTH_COOKIE_SECURE)%'
        http_only: true
        same_site: lax
        lifetime: 2592000
    circuit_breaker:
        failure_threshold: 3
        open_seconds: 60
    http:
        timeout: 5.0
        max_duration: 10.0
```

Environment variables (`.env.local`):

```dotenv
AUTH_BASE_URL=https://auth.example.com
AUTH_PANEL_ID=01234567-89ab-cdef-0123-456789abcdef
AUTH_CLIENT_ID=your-client-id
AUTH_CLIENT_SECRET=your-client-secret
AUTH_COOKIE_SECURE=true
```

Wire up the routes in `config/routes.yaml`:

```yaml
auth_client:
    resource: '@AuthClientBundle/Resources/config/routes.yaml'
```

Wire up the firewall in `config/packages/security.yaml`:

```yaml
security:
    providers:
        in_memory:
            memory: ~

    firewalls:
        login:
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
```

## Wiring up the user mirror

The bundle does not own the user table — the consumer does. Two contracts
must be implemented:

### 1. The entity

Implement `Musikhood\AuthClient\Contract\PanelUserInterface`:

```php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Musikhood\AuthClient\Contract\PanelUserInterface;
use Ramsey\Uuid\UuidInterface;

#[ORM\Entity(repositoryClass: \App\Repository\UserRepository::class)]
#[ORM\Table(name: 'users')]
class User implements PanelUserInterface
{
    // ... see docs/example-entity.php for a full reference implementation
}
```

### 2. The repository

Implement `Musikhood\AuthClient\Contract\PanelUserRepositoryInterface` and
register it as an alias for the interface:

```php
namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Musikhood\AuthClient\Contract\PanelUserInterface;
use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Ramsey\Uuid\UuidInterface;

class UserRepository extends ServiceEntityRepository implements PanelUserRepositoryInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    // ... see docs/example-repository.php
}
```

In `config/services.yaml`, alias the interface to the concrete repository:

```yaml
services:
    Musikhood\AuthClient\Contract\PanelUserRepositoryInterface:
        alias: App\Repository\UserRepository
```

### 3. The schema

See `docs/example-migration.sql` for the schema the entity should match.

## Frontend contract

The frontend never sees the JWT. It just needs:

- `axios.defaults.withCredentials = true` (or the equivalent `fetch` option)
- on `401` from any `/api/*` call: `POST /api/token/refresh`, then retry
- on `401` from `/api/token/refresh`: clear local UI state, redirect to login

This contract is identical to talking to the auth server directly, so an
existing frontend can switch backends without changes.

## License

MIT — see [LICENSE](LICENSE).
