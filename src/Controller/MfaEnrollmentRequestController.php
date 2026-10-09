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
 * Włączenie 2FA przez zalogowanego usera: refresh_token z ciasteczka + `{password}`
 * z body → /api/auth/backend/mfa/enrollment/request → {enrollment_url}.
 * Hasło jest wymagane (sama sesja nie wystarcza — skradzione ciasteczko nie może
 * podpiąć 2FA atakującego). 401 `invalid_credentials`, 409 `mfa_already_enabled`, 429.
 */
class MfaEnrollmentRequestController extends AbstractController
{
    public function __construct(
        private readonly AuthBackendClient $authBackendClient,
        private readonly AuthCookieFactory $cookieFactory,
        private readonly LoggerInterface $logger,
    ) {}

    #[Route('/api/mfa/enrollment/request', name: 'api_mfa_enrollment_request', methods: ['POST'])]
    public function __invoke(Request $request): JsonResponse
    {
        $refreshToken = $request->cookies->get($this->cookieFactory->refreshCookieName());
        if (!is_string($refreshToken) || '' === $refreshToken) {
            return new JsonResponse(['error' => 'Brak autoryzacji.'], Response::HTTP_UNAUTHORIZED);
        }

        $password = MfaControllerSupport::stringField(MfaControllerSupport::payload($request->getContent()), 'password');

        try {
            $url = $this->authBackendClient->requestMfaEnrollment($refreshToken, $password);
        } catch (AuthBackendException $e) {
            $mapped = MfaControllerSupport::map($e);
            if (null !== $mapped) {
                return $mapped;
            }
            $this->logger->error('AuthBackend mfa/enrollment/request failed', ['error' => $e->getMessage()]);

            return new JsonResponse(['error' => 'Usługa uwierzytelniania niedostępna.'], Response::HTTP_SERVICE_UNAVAILABLE);
        }

        $response = new JsonResponse(['enrollment_url' => $url]);
        $response->setEncodingOptions($response->getEncodingOptions() | JSON_UNESCAPED_SLASHES);

        return $response;
    }
}
