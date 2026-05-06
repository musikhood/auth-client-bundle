<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Controller;

use Musikhood\AuthClient\Cookie\AuthCookieFactory;
use Musikhood\AuthClient\Exception\AuthBackendException;
use Musikhood\AuthClient\Exception\AuthBackendUnauthorizedException;
use Musikhood\AuthClient\Http\AuthBackendClient;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Odświeża ciasteczka BEARER + refresh_token. Wywoływane przez interceptor
 * axiosa na froncie po dostaniu 401.
 *
 * Body żądania jest puste. Refresh token niesie przeglądarka w ciasteczku.
 *
 * Jeśli auth server odpowie 401, czyścimy oba ciasteczka. Front przechodzi
 * wtedy do swojej procedury wylogowania.
 */
class RefreshTokenController extends AbstractController
{
    public function __construct(
        private readonly AuthBackendClient $authBackendClient,
        private readonly AuthCookieFactory $cookieFactory,
        private readonly LoggerInterface $logger,
    ) {}

    #[Route('/api/token/refresh', name: 'api_token_refresh', methods: ['POST'])]
    public function __invoke(Request $request): JsonResponse
    {
        $refreshToken = $request->cookies->get($this->cookieFactory->refreshCookieName());
        if (!is_string($refreshToken) || '' === $refreshToken) {
            return $this->unauthorized();
        }

        try {
            $tokens = $this->authBackendClient->refresh($refreshToken);
        } catch (AuthBackendUnauthorizedException) {
            // Refresh token został unieważniony lub wygasł na auth serverze,
            // czyścimy ciasteczka, żeby frontend nie próbował dalej z nieważnymi
            // danymi.
            return $this->unauthorized();
        } catch (AuthBackendException $e) {
            $this->logger->warning('Refresh: auth server nie odpowiedział poprawnie', ['error' => $e->getMessage()]);

            return new JsonResponse(
                ['error' => 'Authentication service unavailable'],
                Response::HTTP_SERVICE_UNAVAILABLE,
            );
        }

        $response = new JsonResponse([], Response::HTTP_OK);
        $this->cookieFactory->applyTokens($response, $tokens);

        return $response;
    }

    private function unauthorized(): JsonResponse
    {
        $response = new JsonResponse(['error' => 'Unauthorized'], Response::HTTP_UNAUTHORIZED);
        $this->cookieFactory->clear($response);

        return $response;
    }
}
