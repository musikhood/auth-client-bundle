<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Contract;

use Ramsey\Uuid\UuidInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Lokalna kopia użytkownika z zewnętrznego serwera auth.
 *
 * Aplikacja sama dostarcza encję (np. Doctrine) i implementuje ten interfejs.
 * Dzięki temu authenticator i sprawdzanie ról nie wiedzą jak konkretnie
 * trzymane są dane.
 *
 * Id pochodzi z claim user_id w JWT. Nie generujemy go lokalnie.
 */
interface PanelUserInterface extends UserInterface
{
    public function getId(): UuidInterface;

    public function getEmail(): string;

    public function getDisplayName(): ?string;

    /** @return list<string> nazwy ról bez prefiksu ROLE_ */
    public function getRolesForPanel(): array;

    public function isDisabled(): bool;

    /**
     * Aktualizuje dane użytkownika świeżymi wartościami z JWT.
     * Implementacja powinna też ustawić aktualny czas ostatniej synchronizacji.
     *
     * @param list<string> $rolesForPanel nazwy ról bez prefiksu ROLE_
     */
    public function syncFromClaims(string $email, ?string $displayName, array $rolesForPanel): void;

    public function markDisabled(bool $disabled): void;
}
