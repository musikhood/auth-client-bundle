<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Controller;

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
 * Drugi krok logowania 2FA: {mfa_token, code | recovery_code, remember_device?, device?}
 * → /api/auth/backend/login/mfa → ciasteczka jak po /api/login.
 * Musi być publiczny (firewall `login` konsumenta).
 */
class LoginMfaController extends AbstractController
{
    public function __construct(
        private readonly AuthBackendClient $authBackendClient,
        private readonly AuthSessionIssuer $sessionIssuer,
        private readonly LoggerInterface $logger,
    ) {}

    #[Route('/api/login/mfa', name: 'api_login_mfa', methods: ['POST'])]
    public function __invoke(Request $request): JsonResponse
    {
        $payload = MfaControllerSupport::payload($request->getContent());
        $mfaToken = MfaControllerSupport::stringField($payload, 'mfa_token');
        $code = MfaControllerSupport::stringField($payload, 'code');
        $recovery = MfaControllerSupport::stringField($payload, 'recovery_code');

        if (null === $mfaToken || (null === $code && null === $recovery)) {
            return new JsonResponse(['error' => 'Brak kodu weryfikacyjnego.'], Response::HTTP_BAD_REQUEST);
        }

        /** @var array<string, mixed>|null $device */
        $device = is_array($payload['device'] ?? null) ? $payload['device'] : null;

        try {
            $tokens = $this->authBackendClient->loginMfa($mfaToken, $code, $recovery, true === ($payload['remember_device'] ?? false), $device);
        } catch (AuthBackendException $e) {
            $mapped = MfaControllerSupport::map($e);
            if (null !== $mapped) {
                return $mapped;
            }
            $this->logger->error('AuthBackend login/mfa failed', ['error' => $e->getMessage()]);

            return new JsonResponse(['error' => 'Usługa uwierzytelniania niedostępna.'], Response::HTTP_SERVICE_UNAVAILABLE);
        }

        return $this->sessionIssuer->issue($tokens);
    }
}
