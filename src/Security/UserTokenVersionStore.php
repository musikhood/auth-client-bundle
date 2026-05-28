<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Security;

use Psr\Cache\CacheItemPoolInterface;
use Ramsey\Uuid\UuidInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Przechowuje ostatnią znaną `tokenVersion` per user, zasilaną webhookiem od
 * auth servera. {@see \Musikhood\AuthClient\Security\JwtCookieAuthenticator}
 * porównuje `ver` z user JWT z tą wartością i odrzuca stare sesje (0s revocation).
 *
 * Świadomie cache PSR (Redis), nie kolumna w encji konsumenta: webhook może
 * przyjść dla usera, którego konsument jeszcze nie zna (nigdy się nie zalogował
 * lokalnie). Reset cache (flush Redisa) = miss = pass — akceptowalny tradeoff:
 * `/me` poll dogoni inwalidację w ~30s.
 */
final readonly class UserTokenVersionStore
{
    private const CACHE_KEY_PREFIX = 'auth_client_token_version_';
    private const TTL_SECONDS = 2592000; // 30d, zgodne z najdłuższą sesją (refresh token)

    public function __construct(
        #[Autowire(service: 'cache.app')]
        private CacheItemPoolInterface $cache,
    ) {}

    public function save(UuidInterface $userId, int $tokenVersion): void
    {
        $item = $this->cache->getItem(self::cacheKey($userId));
        $item->set($tokenVersion)->expiresAfter(self::TTL_SECONDS);
        $this->cache->save($item);
    }

    public function get(UuidInterface $userId): ?int
    {
        $item = $this->cache->getItem(self::cacheKey($userId));
        if (!$item->isHit()) {
            return null;
        }

        $value = $item->get();

        return is_int($value) ? $value : null;
    }

    private static function cacheKey(UuidInterface $userId): string
    {
        return self::CACHE_KEY_PREFIX . $userId->toString();
    }
}
