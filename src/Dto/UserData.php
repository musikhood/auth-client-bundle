<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Dto;

use Ramsey\Uuid\UuidInterface;

/**
 * Dane użytkownika zwracane przez auth server z GET /api/v1/user/me.
 *
 * Używamy ich w {@see \Musikhood\AuthClient\EventListener\AuthValidationListener}
 * jako źródło prawdy do okresowej (~30s) synchronizacji lokalnej kopii
 * użytkownika. Auth server jest jedynym miejscem, w którym żyją role,
 * displayName i flaga disabled — paczka tylko pobiera i propaguje.
 */
final readonly class UserData
{
    /**
     * @param list<string> $roles      globalne role (ROLE_USER, ROLE_ADMIN, ...).
     *                                 Mają znaczenie tylko w panelu admin auth
     *                                 servera. Aplikacje używające modułu je
     *                                 ignorują.
     * @param list<string> $panelRoles role per panel (PUBLISH, EDIT, ...) bez
     *                                 prefiksu ROLE_. To z nich
     *                                 {@see \Musikhood\AuthClient\Contract\PanelUserInterface::getRoles()}
     *                                 buduje finalne ROLE_ używane przez Symfony Security.
     */
    public function __construct(
        public UuidInterface $id,
        public string $email,
        public ?string $displayName,
        public array $roles,
        public ?UuidInterface $panelId,
        public ?string $panelName,
        public array $panelRoles,
        public bool $disabled,
    ) {}
}
