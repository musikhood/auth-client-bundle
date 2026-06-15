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
 *
 * PANEL-AGNOSTYCZNE: `panelId` jest OPCJONALNY. Te same ciasteczka SSO chodzą
 * po wielu panelach, więc token może nie nieść `panel_id` albo nieść id innego
 * panelu — NIE jest to warunek ważności. O dostępie do TEGO panelu rozstrzyga
 * backendowa introspekcja (403), nie claim w tokenie.
 */
final readonly class JwtClaims
{
    /**
     * @param string|null  $panelId claim `panel_id` — informacyjny, opcjonalny
     *                     (patrz docblock klasy). NIE bramkujemy po nim.
     * @param list<string> $panelRoles nazwy ról bez prefiksu ROLE_
     * @param int|null     $tokenVersion claim `ver` — null dla starych tokenów
     *                     wystawionych zanim auth server wdrożył Phase 1
     *                     (kompatybilność wsteczna, wygasną w ciągu TTL access
     *                     tokena, typowo ~15 min)
     */
    public function __construct(
        public UuidInterface $userId,
        public string $email,
        public ?string $displayName,
        public ?string $panelId,
        public ?string $panelName,
        public array $panelRoles,
        public \DateTimeImmutable $issuedAt,
        public \DateTimeImmutable $expiresAt,
        public ?int $tokenVersion = null,
    ) {}
}
