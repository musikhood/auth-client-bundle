<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Controller;

use Musikhood\AuthClient\Cookie\AuthCookieFactory;
use Musikhood\AuthClient\Exception\AuthBackendException;
use Musikhood\AuthClient\Http\AuthBackendClient;
use Musikhood\AuthClient\Security\AuthSessionIssuer;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Step-up 2FA bieżącej sesji (po 403 `mfa_step_up`): refresh_token z ciasteczka
 * + {code | recovery_code} → /api/auth/backend/session/mfa → nowe ciasteczka.
 * Autoryzacja = refresh_token weryfikowany przez auth server, dlatego endpoint
 * jest w publicznym firewallu konsumenta (inaczej introspekcja zwróciłaby
 * 403 mfa_step_up na samym step-upie).
 */
class SessionMfaController extends AbstractController
{
    public function __construct(
        private readonly AuthBackendClient $authBackendClient,
        private readonly AuthSessionIssuer $sessionIssuer,
        private readonly AuthCookieFactory $cookieFactory,
        private readonly LoggerInterface $logger,
    ) {}

    #[Route('/api/session/mfa', name: 'api_session_mfa', methods: ['POST'])]
    public function __invoke(Request $request): JsonResponse
    {
        $refreshToken = $request->cookies->get($this->cookieFactory->refreshCookieName());
        if (!is_string($refreshToken) || '' === $refreshToken) {
            return new JsonResponse(['error' => 'Brak autoryzacji.'], Response::HTTP_UNAUTHORIZED);
        }

        $payload = MfaControllerSupport::payload($request->getContent());
        $code = MfaControllerSupport::stringField($payload, 'code');
        $recovery = MfaControllerSupport::stringField($payload, 'recovery_code');
        if (null === $code && null === $recovery) {
            return new JsonResponse(['error' => 'Brak kodu weryfikacyjnego.'], Response::HTTP_BAD_REQUEST);
        }

        /** @var array<string, mixed>|null $device */
        $device = is_array($payload['device'] ?? null) ? $payload['device'] : null;

        try {
            $tokens = $this->authBackendClient->sessionMfa($refreshToken, $code, $recovery, true === ($payload['remember_device'] ?? false), $device);
        } catch (AuthBackendException $e) {
            // Uwaga: przy złym kodzie / limicie NIE czyścimy ciasteczek — sesja żyje.
            $mapped = MfaControllerSupport::map($e);
            if (null !== $mapped) {
                return $mapped;
            }
            $this->logger->error('AuthBackend session/mfa failed', ['error' => $e->getMessage()]);

            return new JsonResponse(['error' => 'Usługa uwierzytelniania niedostępna.'], Response::HTTP_SERVICE_UNAVAILABLE);
        }

        return $this->sessionIssuer->issue($tokens);
    }
}
