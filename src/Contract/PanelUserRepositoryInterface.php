<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Contract;

use Ramsey\Uuid\UuidInterface;

/**
 * Repozytorium dla {@see PanelUserInterface}.
 * Aplikacja podpina swoje repo Doctrine (lub inną implementację) pod ten
 * interfejs. Moduł sam nigdy nie woła Doctrine bezpośrednio.
 */
interface PanelUserRepositoryInterface
{
    public function findById(UuidInterface $id): ?PanelUserInterface;

    public function findByEmail(string $email): ?PanelUserInterface;

    public function save(PanelUserInterface $user): void;

    public function flush(): void;

    /**
     * Tworzy nowy obiekt użytkownika z claimów JWT.
     * Fabryka jest na repozytorium, żeby moduł nie musiał znać klasy encji.
     *
     * @param list<string> $rolesForPanel nazwy ról bez prefiksu ROLE_
     */
    public function createFromClaims(
        UuidInterface $id,
        string $email,
        ?string $displayName,
        array $rolesForPanel,
    ): PanelUserInterface;
}
