<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Controller;

use Musikhood\AuthClient\EventListener\AuthValidationListener;
use Musikhood\AuthClient\Exception\InvalidJwtException;
use Musikhood\AuthClient\Jwt\WebhookJwtValidator;
use Musikhood\AuthClient\Security\UserTokenVersionStore;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Odbiornik webhooka inwalidacji usera od auth servera (0s revocation).
 *
 * Autoryzacja: webhook ma własną walidację przez {@see WebhookJwtValidator}
 * (podpisany JWT mastera, aud=panel_id konsumenta) — to model jak weryfikacja
 * podpisu webhooków Stripe/GitHub, NIE dziura w security. Konsument MUSI dodać
 * w swoim security.yaml access_control PRZED catch-all `^/api`:
 *
 *   - { path: ^/api/auth-client/webhook/, roles: PUBLIC_ACCESS }
 *
 * To wystarczy dzięki temu, że {@see JwtCookieAuthenticator} paczki ma
 * supports() returning null (lazy mode) — Symfony w lazy mode pomija
 * authenticator dla ścieżek z PUBLIC_ACCESS w access_control.
 *
 * Po walidacji zapisuje nową tokenVersion w store i wymazuje cache
 * `auth_client_validated_<userId>`, żeby kolejny request usera przeszedł pełny
 * cykl walidacji (defense in depth: gdyby webhook się zgubił, `/me` poll dogoni).
 */
class WebhookController extends AbstractController
{
    public function __construct(
        private readonly WebhookJwtValidator $validator,
        private readonly UserTokenVersionStore $store,
        private readonly AuthValidationListener $authValidationListener,
        private readonly LoggerInterface $logger,
    ) {}

    #[Route('/api/auth-client/webhook/user-invalidated', name: 'auth_client_webhook_user_invalidated', methods: ['POST'])]
    public function __invoke(Request $request): JsonResponse
    {
        $token = $this->extractBearer($request);
        if (null === $token) {
            $this->logger->warning('webhook.rejected', [
                'reason' => 'no_bearer',
                'path' => $request->getPathInfo(),
            ]);

            return new JsonResponse(['error' => 'Brak autoryzacji.'], Response::HTTP_UNAUTHORIZED);
        }

        try {
            $claims = $this->validator->validate($token);
        } catch (InvalidJwtException $e) {
            $this->logger->warning('webhook.rejected', [
                'reason' => $e->getMessage(),
                'path' => $request->getPathInfo(),
            ]);

            return new JsonResponse(['error' => 'Brak autoryzacji.'], Response::HTTP_UNAUTHORIZED);
        }

        $this->store->save($claims->userId, $claims->tokenVersion);
        $this->authValidationListener->invalidateValidatedCache($claims->userId);

        $this->logger->info('webhook.received', [
            'user_id' => $claims->userId->toString(),
            'reason' => $claims->reason,
            'panel_id' => $claims->panelId,
            'new_token_version' => $claims->tokenVersion,
        ]);

        return new JsonResponse(['ok' => true], Response::HTTP_OK);
    }

    private function extractBearer(Request $request): ?string
    {
        $header = $request->headers->get('Authorization');
        if (is_string($header) && str_starts_with($header, 'Bearer ')) {
            $token = substr($header, 7);
            if ('' !== $token) {
                return $token;
            }
        }

        return null;
    }
}
