<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Dto;

use Ramsey\Uuid\UuidInterface;

/**
 * Dane użytkownika zwracane przez auth server z GET /api/v1/user/me.
 * Używamy ich przy introspekcji (validation listener) i przy leniwym
 * upsercie kopii użytkownika w authenticatorze.
 */
final readonly class UserData
{
    /**
     * @param list<string> $roles globalne role (ROLE_USER, ROLE_ADMIN, ...).
     *                            Mają znaczenie tylko w panelu admin auth
     *                            servera. Aplikacje używające modułu je
     *                            ignorują.
     */
    public function __construct(
        public UuidInterface $id,
        public string $email,
        public array $roles,
    ) {}
}
