<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Security;

use Musikhood\AuthClient\Cookie\AuthCookieFactory;
use Musikhood\AuthClient\Dto\TokenPair;
use Musikhood\AuthClient\Exception\InvalidJwtException;
use Musikhood\AuthClient\Jwt\JwtValidator;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Wspólne zakończenie loginu / kroku 2FA / step-upu: lokalna walidacja JWT
 * wydanego przez auth server, upsert lokalnej kopii usera, ciasteczka HttpOnly.
 */
final readonly class AuthSessionIssuer
{
    public function __construct(
        private JwtValidator $jwtValidator,
        private UserMirrorSyncer $userMirrorSyncer,
        private AuthCookieFactory $cookieFactory,
        private LoggerInterface $logger,
    ) {}

    public function issue(TokenPair $tokens): JsonResponse
    {
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
}
