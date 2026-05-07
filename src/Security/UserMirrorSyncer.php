<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Security;

use Musikhood\AuthClient\Contract\PanelUserInterface;
use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Musikhood\AuthClient\Dto\UserData;
use Musikhood\AuthClient\Jwt\JwtClaims;

/**
 * Lazy-upsert lokalnej kopii użytkownika z dwóch źródeł:
 *
 *   1. {@see self::upsert()} — woła authenticator przy każdym
 *      uwierzytelnionym żądaniu. Wkład: claimy świeżo zwalidowanego JWT.
 *      Brak flagi disabled (login = na pewno nie zablokowany).
 *
 *   2. {@see self::syncFromMe()} — woła AuthValidationListener po udanej
 *      introspekcji /me. Wkład: pełna kopia z auth servera, w tym
 *      flaga disabled. To jest źródło prawdy do propagacji zmian
 *      ról / displayName / disabled bez konieczności podbijania
 *      tokenVersion w auth serverze.
 *
 * Flush robimy tylko jeśli coś się faktycznie zmieniło — typowy request
 * nie kosztuje DB write'a.
 */
final readonly class UserMirrorSyncer
{
    public function __construct(
        private PanelUserRepositoryInterface $userRepository,
    ) {}

    public function upsert(JwtClaims $claims): PanelUserInterface
    {
        $existing = $this->userRepository->findById($claims->userId);

        if (null === $existing) {
            $user = $this->userRepository->createFromClaims(
                id: $claims->userId,
                email: $claims->email,
                displayName: $claims->displayName,
                rolesForPanel: $claims->panelRoles,
            );
            $this->userRepository->save($user);
            $this->userRepository->flush();

            return $user;
        }

        if ($this->hasChangedFromClaims($existing, $claims)) {
            $existing->syncFromClaims(
                email: $claims->email,
                displayName: $claims->displayName,
                rolesForPanel: $claims->panelRoles,
            );
            $this->userRepository->flush();
        }

        return $existing;
    }

    /**
     * Synchronizuje lokalną kopię z payloadu /me.
     *
     * Aktualizuje email, displayName, role per-panel i flagę disabled.
     * Jeśli auth server zwrócił panelRoles dla innego panelu niż ten, do
     * którego zalogowany jest aktualny user — i tak je nadpisujemy, bo
     * panelId w JWT (aud) jest pojedynczy i auth server zwraca panelRoles
     * dla tego konkretnego panelu.
     */
    public function syncFromMe(UserData $data): PanelUserInterface
    {
        $existing = $this->userRepository->findById($data->id);

        if (null === $existing) {
            // Nie powinno się zdarzyć — authenticator robi upsert wcześniej.
            // Defensywnie tworzymy mimo wszystko, żeby kolejny request nie
            // padł na null.
            $user = $this->userRepository->createFromClaims(
                id: $data->id,
                email: $data->email,
                displayName: $data->displayName,
                rolesForPanel: $data->panelRoles,
            );
            $user->markDisabled($data->disabled);
            $this->userRepository->save($user);
            $this->userRepository->flush();

            return $user;
        }

        $changed = false;

        if ($this->hasChangedFromUserData($existing, $data)) {
            $existing->syncFromClaims(
                email: $data->email,
                displayName: $data->displayName,
                rolesForPanel: $data->panelRoles,
            );
            $changed = true;
        }

        if ($existing->isDisabled() !== $data->disabled) {
            $existing->markDisabled($data->disabled);
            $changed = true;
        }

        if ($changed) {
            $this->userRepository->flush();
        }

        return $existing;
    }

    private function hasChangedFromClaims(PanelUserInterface $user, JwtClaims $claims): bool
    {
        if ($user->getEmail() !== $claims->email) {
            return true;
        }
        if ($user->getDisplayName() !== $claims->displayName) {
            return true;
        }

        return $this->panelRolesChanged($user->getRolesForPanel(), $claims->panelRoles);
    }

    private function hasChangedFromUserData(PanelUserInterface $user, UserData $data): bool
    {
        if ($user->getEmail() !== $data->email) {
            return true;
        }
        if ($user->getDisplayName() !== $data->displayName) {
            return true;
        }

        return $this->panelRolesChanged($user->getRolesForPanel(), $data->panelRoles);
    }

    /**
     * @param list<string> $current
     * @param list<string> $incoming
     */
    private function panelRolesChanged(array $current, array $incoming): bool
    {
        sort($current);
        sort($incoming);

        return $current !== $incoming;
    }
}
