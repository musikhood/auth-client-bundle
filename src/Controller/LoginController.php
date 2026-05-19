<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Controller;

use Musikhood\AuthClient\Cookie\AuthCookieFactory;
use Musikhood\AuthClient\Exception\AuthBackendException;
use Musikhood\AuthClient\Exception\AuthBackendUnauthorizedException;
use Musikhood\AuthClient\Exception\InvalidJwtException;
use Musikhood\AuthClient\Http\AuthBackendClient;
use Musikhood\AuthClient\Jwt\JwtValidator;
use Musikhood\AuthClient\Security\UserMirrorSyncer;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Logowanie. Wymienia {username, password} na parę ciasteczek HttpOnly
 * (BEARER + refresh_token), takich samych jakie ustawia sam auth server.
 *
 * Frontend nigdy nie widzi tokenów. Używa tylko `withCredentials: true`,
 * przeglądarka sama dokleja ciasteczka do każdego żądania.
 */
class LoginController extends AbstractController
{
    public function __construct(
        private readonly AuthBackendClient $authBackendClient,
        private readonly JwtValidator $jwtValidator,
        private readonly UserMirrorSyncer $userMirrorSyncer,
        private readonly AuthCookieFactory $cookieFactory,
        private readonly LoggerInterface $logger,
    ) {}

    #[Route('/api/login', name: 'api_login', methods: ['POST'])]
    public function __invoke(Request $request): JsonResponse
    {
        /** @var array<string, mixed> $payload */
        $payload = json_decode($request->getContent(), true) ?? [];

        // Frontend wysyła {username, password}; username to email.
        $email = $this->stringField($payload, 'username') ?? $this->stringField($payload, 'email');
        $password = $this->stringField($payload, 'password');

        if (null === $email || null === $password) {
            return new JsonResponse(['error' => 'Brak loginu lub hasła.'], Response::HTTP_BAD_REQUEST);
        }

        try {
            $tokens = $this->authBackendClient->login($email, $password);
        } catch (AuthBackendUnauthorizedException) {
            return new JsonResponse(['error' => 'Nieprawidłowy login lub hasło.'], Response::HTTP_UNAUTHORIZED);
        } catch (AuthBackendException $e) {
            $this->logger->error('AuthBackend login failed', ['error' => $e->getMessage()]);

            return new JsonResponse(['error' => 'Usługa uwierzytelniania niedostępna.'], Response::HTTP_SERVICE_UNAVAILABLE);
        }

        try {
            $claims = $this->jwtValidator->validate($tokens->accessToken);
        } catch (InvalidJwtException $e) {
            // Auth server wystawił token, którego nie potrafimy zweryfikować
            // lokalnie. Najczęściej źle ustawione AUTH_PANEL_ID lub AUTH_BASE_URL.
            $this->logger->critical('Login: auth server wystawił JWT, którego nie da się zweryfikować', ['error' => $e->getMessage()]);

            return new JsonResponse(['error' => 'Błąd konfiguracji uwierzytelniania.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $this->userMirrorSyncer->upsert($claims);

        $response = new JsonResponse([], Response::HTTP_OK);
        $this->cookieFactory->applyTokens($response, $tokens);

        return $response;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function stringField(array $payload, string $key): ?string
    {
        $value = $payload[$key] ?? null;

        return is_string($value) && '' !== $value ? $value : null;
    }
}
