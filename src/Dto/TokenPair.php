<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Dto;

/**
 * Para tokenów zwracana przez auth server przy login i refresh.
 *
 * `accessToken` to krótko żyjący JWT (~15 min).
 * `refreshToken` jest nieczytelny, jednorazowy, z długim TTL (30 dni).
 * Refresh token nigdy nie może trafić do frontu.
 */
final readonly class TokenPair
{
    public function __construct(
        public string $accessToken,
        public string $refreshToken,
        public \DateTimeImmutable $refreshTokenExpiresAt,
    ) {}
}
