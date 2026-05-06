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
 * Zwraca dane zalogowanego użytkownika z lokalnej kopii. Nie woła auth servera.
 *
 * Format zgodny z typem User na froncie: {id, email, roles, disabled}.
 * Pole `roles` to role panelu (z prefiksem ROLE_), wyliczone z `panel_roles`
 * z JWT. Globalnych ról z claimu `roles` tu nie wystawiamy.
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
                'roles' => $user->getRoles(),
                'disabled' => $user->isDisabled(),
            ],
            Response::HTTP_OK,
        );
    }
}
