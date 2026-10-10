<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Controller;

use Musikhood\AuthClient\Exception\AuthBackendException;
use Musikhood\AuthClient\Exception\AuthBackendForbiddenException;
use Musikhood\AuthClient\Exception\AuthBackendMfaEnrollmentRequiredException;
use Musikhood\AuthClient\Exception\AuthBackendMfaRequiredException;
use Musikhood\AuthClient\Exception\AuthBackendTooManyAttemptsException;
use Musikhood\AuthClient\Exception\AuthBackendUnauthorizedException;
use Musikhood\AuthClient\Http\AuthBackendClient;
use Musikhood\AuthClient\Http\AuthErrorResponse;
use Musikhood\AuthClient\Security\AuthSessionIssuer;
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
 *
 * 2FA (0.7): 401 `mfa_required` (z `mfa_token`, BEZ ciasteczek) i 403
 * `mfa_enrollment_required` (z `enrollment_url`) przechodzą do frontu 1:1 —
 * drugi krok to POST /api/login/mfa. Inne 401 dalej = "Nieprawidłowy login".
 */
class LoginController extends AbstractController
{
    public function __construct(
        private readonly AuthBackendClient $authBackendClient,
        private readonly AuthSessionIssuer $sessionIssuer,
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

        /** @var array<string, mixed>|null $device */
        $device = is_array($payload['device'] ?? null) ? $payload['device'] : null;

        try {
            $tokens = $this->authBackendClient->login($email, $password, $device);
        } catch (AuthBackendMfaRequiredException $e) {
            return AuthErrorResponse::create($e->getMessage(), AuthErrorResponse::CODE_MFA_REQUIRED, Response::HTTP_UNAUTHORIZED, [
                'mfa_token' => $e->mfaToken,
                'methods' => $e->methods,
            ]);
        } catch (AuthBackendUnauthorizedException) {
            return AuthErrorResponse::create('Nieprawidłowy login lub hasło.', AuthErrorResponse::CODE_INVALID_CREDENTIALS, Response::HTTP_UNAUTHORIZED);
        } catch (AuthBackendMfaEnrollmentRequiredException $e) {
            return AuthErrorResponse::create($e->getMessage(), AuthErrorResponse::CODE_MFA_ENROLLMENT_REQUIRED, Response::HTTP_FORBIDDEN, [
                'enrollment_url' => $e->enrollmentUrl,
            ]);
        } catch (AuthBackendForbiddenException $e) {
            // 403 z auth servera — kredensje OK, ale brak dostępu do panelu lub
            // konto disabled. Tekst z auth servera niesie konkretną przyczynę,
            // propagujemy go bez zmian, żeby user widział "nie masz dostępu" a
            // nie "usługa niedostępna".
            return new JsonResponse(['error' => $e->getMessage()], Response::HTTP_FORBIDDEN);
        } catch (AuthBackendTooManyAttemptsException $e) {
            return MfaControllerSupport::tooManyAttempts($e);
        } catch (AuthBackendException $e) {
            $this->logger->error('AuthBackend login failed', ['error' => $e->getMessage()]);

            return new JsonResponse(['error' => 'Usługa uwierzytelniania niedostępna.'], Response::HTTP_SERVICE_UNAVAILABLE);
        }

        return $this->sessionIssuer->issue($tokens);
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
