<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Controller;

use Musikhood\AuthClient\Contract\PanelUserInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * Zwraca dane zalogowanego użytkownika z lokalnej kopii.
 *
 * Lokalna kopia jest aktualizowana z auth servera w dwóch miejscach:
 *   - przy login / refresh — z claimów świeżego JWT (email, displayName, role per panel),
 *   - co ~30s przez {@see \Musikhood\AuthClient\EventListener\AuthValidationListener}
 *     — z pełnego payloadu /api/v1/user/me (w tym flaga disabled).
 *
 * Pole `roles` to wynik {@see PanelUserInterface::getRoles()} — role panelu z
 * prefiksem ROLE_, wzbogacone o ROLE_USER. Globalnych ról z claimu `roles`
 * nie wystawiamy.
 */
class MeController extends AbstractController
{
    #[Route('/api/v1/user/me', name: 'api_user_me', methods: ['GET'])]
    #[IsGranted('IS_AUTHENTICATED_FULLY')]
    public function __invoke(): JsonResponse
    {
        /** @var PanelUserInterface $user */
        $user = $this->getUser();

        return new JsonResponse(
            [
                'id' => $user->getId()->toString(),
                'email' => $user->getEmail(),
                'displayName' => $user->getDisplayName(),
                'roles' => $user->getRoles(),
                'disabled' => $user->isDisabled(),
            ],
            Response::HTTP_OK,
        );
    }
}
