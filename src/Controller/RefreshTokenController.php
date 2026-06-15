<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Controller;

use Musikhood\AuthClient\Cookie\AuthCookieFactory;
use Musikhood\AuthClient\Exception\AuthBackendException;
use Musikhood\AuthClient\Exception\AuthBackendForbiddenException;
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
        } catch (AuthBackendForbiddenException $e) {
            // 403 = brak dostępu do panelu (sesja ŻYJE). NIGDY nie czyścimy
            // ciasteczek przy 403 — to nie jest nieważna sesja, tylko brak
            // dostępu do TEGO panelu. Front (paczka JS) klasyfikuje to jako
            // PanelAccessDeniedError i zostaje na loginie bez wylogowania z
            // innych paneli. (Po relaksie panel-ownership backend-refresh nie
            // powinien zwracać 403, ale utwardzamy kontrakt defensywnie.)
            $this->logger->info('Refresh: 403 z auth servera — brak dostępu do panelu, NIE czyścimy ciasteczek', [
                'reason' => $e->getMessage(),
            ]);

            return new JsonResponse(['error' => $e->getMessage()], Response::HTTP_FORBIDDEN);
        } catch (AuthBackendUnauthorizedException) {
            // 401 = refresh token unieważniony/wygasły na auth serverze. To
            // jedyny przypadek czyszczenia ciasteczek — realna nieważność sesji.
            return $this->unauthorized();
        } catch (AuthBackendException $e) {
            // 5xx/transport — master niedostępny. NIE czyścimy ciasteczek (to nie
            // jest odmowa, tylko awaria). 503, front spróbuje ponownie.
            $this->logger->warning('Refresh: auth server nie odpowiedział poprawnie', ['error' => $e->getMessage()]);

            return new JsonResponse(
                ['error' => 'Usługa uwierzytelniania niedostępna.'],
                Response::HTTP_SERVICE_UNAVAILABLE,
            );
        }

        $response = new JsonResponse([], Response::HTTP_OK);
        $this->cookieFactory->applyTokens($response, $tokens);

        return $response;
    }

    private function unauthorized(): JsonResponse
    {
        $response = new JsonResponse(['error' => 'Brak autoryzacji.'], Response::HTTP_UNAUTHORIZED);
        $this->cookieFactory->clear($response);

        return $response;
    }
}
