<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Security;

use Musikhood\AuthClient\Contract\PanelUserInterface;
use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Musikhood\AuthClient\Jwt\JwtClaims;

/**
 * Lazy-upsert lokalnej kopii użytkownika na podstawie claimów JWT.
 *
 * Wywoływany przez authenticator przy każdym uwierzytelnionym żądaniu.
 * Flush wykonujemy tylko gdy email lub role faktycznie się zmieniły.
 * Dzięki temu typowy request niewiele kosztuje.
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
                displayName: $claims->username,
                rolesForPanel: $claims->panelRoles,
            );
            $this->userRepository->save($user);
            $this->userRepository->flush();

            return $user;
        }

        if ($this->hasChanged($existing, $claims)) {
            $existing->syncFromClaims(
                email: $claims->email,
                displayName: $claims->username,
                rolesForPanel: $claims->panelRoles,
            );
            $this->userRepository->flush();
        }

        return $existing;
    }

    private function hasChanged(PanelUserInterface $user, JwtClaims $claims): bool
    {
        if ($user->getEmail() !== $claims->email) {
            return true;
        }
        if ($user->getDisplayName() !== $claims->username) {
            return true;
        }

        $current = $user->getRolesForPanel();
        sort($current);
        $incoming = $claims->panelRoles;
        sort($incoming);

        return $current !== $incoming;
    }
}
