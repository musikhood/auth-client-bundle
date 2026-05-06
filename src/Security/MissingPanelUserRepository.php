<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Security;

use Musikhood\AuthClient\Contract\PanelUserInterface;
use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Ramsey\Uuid\UuidInterface;

/**
 * Placeholder rejestrowany automatycznie przez {@see \Musikhood\AuthClient\DependencyInjection\Compiler\EnsurePanelUserRepositoryPass}
 * gdy konsument nie podpiął jeszcze własnej implementacji
 * {@see PanelUserRepositoryInterface}.
 *
 * Dzięki temu `composer require musikhood/auth-client-bundle` i automatyczne
 * `cache:clear` w post-install przechodzą bez błędu autowire — nawet gdy
 * konsument dopiero zaczyna integrację i nie zdążył jeszcze utworzyć encji
 * User i repo.
 *
 * Każda metoda rzuca {@see \RuntimeException} z jasnym komunikatem
 * kierującym do README. Pierwsze realne wywołanie auth flow (login, /me,
 * refresh) zatrzyma aplikację z wytłumaczeniem co dokładnie dodać.
 */
final class MissingPanelUserRepository implements PanelUserRepositoryInterface
{
    public function findById(UuidInterface $id): ?PanelUserInterface
    {
        $this->fail();
    }

    public function findByEmail(string $email): ?PanelUserInterface
    {
        $this->fail();
    }

    public function save(PanelUserInterface $user): void
    {
        $this->fail();
    }

    public function flush(): void
    {
        $this->fail();
    }

    public function createFromClaims(
        UuidInterface $id,
        string $email,
        ?string $displayName,
        array $rolesForPanel,
    ): PanelUserInterface {
        $this->fail();
    }

    private function fail(): never
    {
        throw new \RuntimeException(
            'auth-client-bundle: PanelUserRepositoryInterface nie jest podpięty. '
            . 'Stwórz UserRepository implementujący Musikhood\\AuthClient\\Contract\\PanelUserRepositoryInterface '
            . 'i dodaj atrybut #[AsAlias(id: PanelUserRepositoryInterface::class)] na klasie. '
            . 'Pełna instrukcja: https://github.com/musikhood/auth-client-bundle#33-stwórz-userrepository'
        );
    }
}
