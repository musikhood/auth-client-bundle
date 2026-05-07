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
 *      uwierzytelnionym żądaniu. Tylko BOOTSTRAP — tworzy lokalną kopię
 *      przy pierwszym kontakcie z userem. Przy istniejącej kopii NIE
 *      modyfikuje żadnych pól, bo claimy JWT mogą być stale (auth server
 *      nie podbija tokenVersion przy zmianach ról / displayName).
 *
 *   2. {@see self::syncFromMe()} — woła AuthValidationListener po udanej
 *      introspekcji /me (cache TTL ~30s). Pełen update lokalnej kopii
 *      (email, displayName, role per-panel, disabled). To jedyne źródło
 *      prawdy do propagacji zmian wykonanych w panelu admin auth servera.
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

        if (null !== $existing) {
            // Lokalna kopia istnieje — nic nie ruszamy. Pełna synchronizacja
            // (email, displayName, role per-panel, disabled) jest robotą
            // syncFromMe() wołanego przez AuthValidationListener z TTL ~30s.
            // Gdyby authenticator nadpisywał tutaj polami z JWT, claimy
            // sprzed zmiany ról cofałyby świeżo-zsynchronizowane wartości
            // przy każdym kolejnym requeście (auth server nie podbija
            // tokenVersion przy zmianach ról, więc JWT może być stale).
            return $existing;
        }

        // Pierwszy kontakt z tym userem w mikroserwisie — bootstrap z
        // claimów JWT. Po pierwszym /me (max ~30s) syncFromMe nadpisze
        // świeżymi danymi z auth servera, jeśli różnią się od JWT.
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

    private function hasChangedFromUserData(PanelUserInterface $user, UserData $data): bool
    {
        if ($user->getEmail() !== $data->email) {
            return true;
        }
        if ($user->getDisplayName() !== $data->displayName) {
            return true;
        }

        $current = $user->getRolesForPanel();
        sort($current);
        $incoming = $data->panelRoles;
        sort($incoming);

        return $current !== $incoming;
    }
}
