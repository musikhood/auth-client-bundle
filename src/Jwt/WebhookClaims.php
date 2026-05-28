<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Jwt;

use Ramsey\Uuid\UuidInterface;

/**
 * Claimy webhooka inwalidacji usera od auth servera. Osobny VO od JwtClaims
 * (user JWT) — webhook niesie inne claimy: `sub` (user_id), `aud` (panel_id
 * konsumenta), `reason`, `panel_id`, `ver`. Instancjonowany ręcznie przez
 * WebhookJwtValidator.
 */
final readonly class WebhookClaims
{
    public function __construct(
        public UuidInterface $userId,
        public string $reason,
        public ?string $panelId,
        public int $tokenVersion,
        public \DateTimeImmutable $issuedAt,
        public \DateTimeImmutable $expiresAt,
    ) {}
}
