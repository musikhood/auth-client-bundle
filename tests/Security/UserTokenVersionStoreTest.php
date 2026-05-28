<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Security;

use Musikhood\AuthClient\Security\UserTokenVersionStore;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Ramsey\Uuid\Uuid;

/**
 * save/get round-trip + zachowanie przy miss (flush cache / TTL). Cache mockowany.
 */
final class UserTokenVersionStoreTest extends TestCase
{
    public function testSavePersistsVersionWithTtl(): void
    {
        $userId = Uuid::uuid4();
        $expectedKey = 'auth_client_token_version_' . $userId->toString();

        $item = $this->createMock(CacheItemInterface::class);
        $item->expects(self::once())->method('set')->with(5)->willReturnSelf();
        $item->expects(self::once())->method('expiresAfter')->with(2592000)->willReturnSelf();

        $cache = $this->createMock(CacheItemPoolInterface::class);
        $cache->expects(self::once())->method('getItem')->with($expectedKey)->willReturn($item);
        $cache->expects(self::once())->method('save')->with($item);

        (new UserTokenVersionStore($cache))->save($userId, 5);
    }

    public function testGetReturnsStoredVersion(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->method('isHit')->willReturn(true);
        $item->method('get')->willReturn(8);

        $cache = $this->createMock(CacheItemPoolInterface::class);
        $cache->method('getItem')->willReturn($item);

        self::assertSame(8, (new UserTokenVersionStore($cache))->get(Uuid::uuid4()));
    }

    public function testGetReturnsNullOnMiss(): void
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->method('isHit')->willReturn(false);

        $cache = $this->createMock(CacheItemPoolInterface::class);
        $cache->method('getItem')->willReturn($item);

        self::assertNull((new UserTokenVersionStore($cache))->get(Uuid::uuid4()));
    }

    public function testGetReturnsNullWhenStoredValueNotInt(): void
    {
        // Defensywnie: gdyby w cache wylądowało coś dziwnego (zmiana formatu),
        // get() zwraca null zamiast rzucać type error.
        $item = $this->createMock(CacheItemInterface::class);
        $item->method('isHit')->willReturn(true);
        $item->method('get')->willReturn('corrupted');

        $cache = $this->createMock(CacheItemPoolInterface::class);
        $cache->method('getItem')->willReturn($item);

        self::assertNull((new UserTokenVersionStore($cache))->get(Uuid::uuid4()));
    }
}
