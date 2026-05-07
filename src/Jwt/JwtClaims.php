<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Jwt;

use Ramsey\Uuid\UuidInterface;

/**
 * Zdekodowany i zweryfikowany payload JWT z auth servera. Gotowy dla
 * authenticatora.
 *
 * Globalnych `roles` z tokenu tu nie trzymamy. Mają sens tylko w panelu admin
 * auth servera. Autoryzacja w aplikacji opiera się o {@see self::$panelRoles}
 * (nazwy ról bez prefiksu ROLE_).
 */
final readonly class JwtClaims
{
    /**
     * @param list<string> $panelRoles nazwy ról bez prefiksu ROLE_
     */
    public function __construct(
        public UuidInterface $userId,
        public string $email,
        public ?string $displayName,
        public string $panelId,
        public ?string $panelName,
        public array $panelRoles,
        public \DateTimeImmutable $issuedAt,
        public \DateTimeImmutable $expiresAt,
    ) {}
}
