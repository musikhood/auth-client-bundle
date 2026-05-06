<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Controller;

use Musikhood\AuthClient\Cookie\AuthCookieFactory;
use Musikhood\AuthClient\Exception\AuthBackendException;
use Musikhood\AuthClient\Http\AuthBackendClient;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Wylogowanie. Czyści oba ciasteczka i unieważnia refresh_token na auth
 * serverze.
 *
 * Idempotentny: wywołanie bez ciasteczek też zwraca 200 i czyści ewentualne
 * resztki. Stara ścieżka `/api/token/invalidate` zostaje jako alias, żeby
 * front nie wymagał zmian.
 */
class LogoutController extends AbstractController
{
    public function __construct(
        private readonly AuthBackendClient $authBackendClient,
        private readonly AuthCookieFactory $cookieFactory,
        private readonly LoggerInterface $logger,
    ) {}

    #[Route('/api/logout', name: 'api_logout', methods: ['POST'])]
    #[Route('/api/token/invalidate', name: 'api_token_invalidate', methods: ['POST'])]
    public function __invoke(Request $request): JsonResponse
    {
        $refreshToken = $request->cookies->get($this->cookieFactory->refreshCookieName());

        if (is_string($refreshToken) && '' !== $refreshToken) {
            try {
                $this->authBackendClient->logout($refreshToken);
            } catch (AuthBackendException $e) {
                // Auth server może być chwilowo niedostępny. I tak czyścimy
                // lokalne ciasteczka. Refresh_token i tak wygaśnie po stronie
                // auth servera.
                $this->logger->warning('Logout: nie udało się unieważnić tokenu na auth serverze', [
                    'error' => $e->getMessage(),
                ]);
            }
        }

        $response = new JsonResponse([], Response::HTTP_OK);
        $this->cookieFactory->clear($response);

        return $response;
    }
}
