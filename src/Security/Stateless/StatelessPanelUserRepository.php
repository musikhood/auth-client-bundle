<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Security\Stateless;

use Musikhood\AuthClient\Contract\PanelUserInterface;
use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Ramsey\Uuid\UuidInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Default user repository when the application does not provide its own
 * {@see PanelUserRepositoryInterface} — no entity, no table, nothing to
 * configure.
 *
 * Users live in two layers:
 *   1. a per-request identity map, so the authenticator and the validation
 *      listener operate on the SAME object (roles synced from /me are visible
 *      to the controller) — cleared by `kernel.reset` (FrankenPHP / RoadRunner
 *      worker mode);
 *   2. a snapshot in `cache.app` written on flush(). It keeps the last /me
 *      state across requests and processes, so a role change made in the
 *      auth-panel propagates within the validation TTL (~30 s) exactly like
 *      the persisted mirror — instead of waiting for the next JWT refresh
 *      (the auth server does not bump the token version on role changes).
 *
 * Losing the cache is harmless: the user is rebuilt from the JWT claims and
 * re-synced by the next introspection.
 */
final class StatelessPanelUserRepository implements PanelUserRepositoryInterface, ResetInterface
{
    private const CACHE_KEY_PREFIX = 'auth_client_user_';
    private const SNAPSHOT_TTL_SECONDS = 86400;

    /** @var array<string, StatelessPanelUser> */
    private array $identityMap = [];

    public function __construct(
        #[Autowire(service: 'cache.app')]
        private readonly CacheItemPoolInterface $cache,
        private readonly LoggerInterface $logger,
    ) {}

    public function findById(UuidInterface $id): ?PanelUserInterface
    {
        $key = $id->toString();
        if (isset($this->identityMap[$key])) {
            return $this->identityMap[$key];
        }

        $item = $this->cache->getItem(self::CACHE_KEY_PREFIX . $key);
        if (!$item->isHit()) {
            return null;
        }

        $data = $item->get();
        if (!\is_array($data)) {
            return null;
        }

        try {
            /** @var array{id: string, email: string, displayName: ?string, rolesForPanel: list<string>, disabled: bool} $data */
            $user = StatelessPanelUser::fromArray($data);
        } catch (\Throwable $e) {
            // Snapshot from an incompatible version — rebuild from the JWT.
            $this->logger->info('auth-client: ignoring unreadable user snapshot', ['user_id' => $key, 'error' => $e->getMessage()]);

            return null;
        }

        return $this->identityMap[$key] = $user;
    }

    public function findByEmail(string $email): ?PanelUserInterface
    {
        // Stateless mode has no index by e-mail; only users seen in this request are known.
        foreach ($this->identityMap as $user) {
            if (0 === strcasecmp($user->getEmail(), $email)) {
                return $user;
            }
        }

        return null;
    }

    public function save(PanelUserInterface $user): void
    {
        if (!$user instanceof StatelessPanelUser) {
            throw new \InvalidArgumentException(sprintf('%s stores only %s, got %s.', self::class, StatelessPanelUser::class, $user::class));
        }

        $key = $user->getId()->toString();
        $this->identityMap[$key] = $user;
    }

    public function flush(): void
    {
        // UserMirrorSyncer mutates loaded users in place and then flushes —
        // persist every user touched in this request, not only save()d ones.
        foreach ($this->identityMap as $key => $user) {
            $item = $this->cache->getItem(self::CACHE_KEY_PREFIX . $key);
            $item->set($user->toArray());
            $item->expiresAfter(self::SNAPSHOT_TTL_SECONDS);
            $this->cache->saveDeferred($item);
        }
        $this->cache->commit();
    }

    /**
     * @param list<string> $rolesForPanel
     */
    public function createFromClaims(UuidInterface $id, string $email, ?string $displayName, array $rolesForPanel): PanelUserInterface
    {
        return new StatelessPanelUser($id, $email, $displayName, array_values($rolesForPanel));
    }

    public function reset(): void
    {
        $this->identityMap = [];
    }
}
