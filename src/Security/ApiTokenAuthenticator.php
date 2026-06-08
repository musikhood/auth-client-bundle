<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Security;

use Musikhood\AuthClient\Exception\AuthBackendException;
use Musikhood\AuthClient\Http\AuthBackendClient;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * Uwierzytelnia żądania maszynowe na podstawie nagłówka X-Api-Token
 * (per-user-per-panel API token z auth servera). Drugi sposób autoryzacji
 * obok {@see JwtCookieAuthenticator} — współistnieją w tym samym firewallu.
 *
 * supports() = true tylko gdy nagłówek obecny → bez niego false i request leci
 * do JwtCookieAuthenticatora bez zmian. Weryfikacja live przez introspekcję na
 * auth serverze (paczka nie trzyma kopii hasha) → rewokacja jest natychmiastowa.
 *
 * Role biorą się z panelRoles (per panel), każda z prefiksem ROLE_ — jak w
 * JwtCookieAuthenticator, więc istniejące #[IsGranted('ROLE_PUBLISH')] działają.
 * Fail-closed: auth server niedostępny → 401.
 */
final class ApiTokenAuthenticator extends AbstractAuthenticator implements \Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface
{
    public function __construct(
        private readonly AuthBackendClient $authBackendClient,
        private readonly UserMirrorSyncer $userMirrorSyncer,
        private readonly LoggerInterface $logger,
        private readonly string $apiTokenHeader,
        private readonly string $authPanelId,
    ) {}

    public function supports(Request $request): bool
    {
        return $request->headers->has($this->apiTokenHeader);
    }

    public function authenticate(Request $request): Passport
    {
        $rawToken = $request->headers->get($this->apiTokenHeader);
        if (!is_string($rawToken) || '' === $rawToken) {
            throw new CustomUserMessageAuthenticationException('Brak tokenu API.');
        }

        try {
            $data = $this->authBackendClient->introspectApiToken($rawToken);
        } catch (AuthBackendException $e) {
            // Fail-closed: bez potwierdzenia od auth servera nie autoryzujemy.
            $this->logger->warning('auth_client_api_token_backend_unavailable', ['error' => $e->getMessage()]);

            throw new CustomUserMessageAuthenticationException('Auth server niedostępny — nie można zweryfikować tokenu.', previous: $e);
        }

        if (null === $data) {
            throw new CustomUserMessageAuthenticationException('Token API nieprawidłowy lub unieważniony.');
        }

        // Izolacja paneli (warstwa po stronie konsumenta): auth server już
        // wymusza token.panelId === callingPanel.id, ale weryfikujemy też tutaj,
        // żeby token wystawiony dla innego panelu pod tym samym client_id
        // (gdyby konfiguracja się rozjechała) nie przeszedł.
        if (null === $data->panelId || $data->panelId->toString() !== $this->authPanelId) {
            $this->logger->warning('auth_client_api_token_panel_mismatch', [
                'token_panel' => $data->panelId?->toString(),
                'configured_panel' => $this->authPanelId,
            ]);

            throw new CustomUserMessageAuthenticationException('Token API nie należy do tego panelu.');
        }

        if ($data->disabled) {
            throw new CustomUserMessageAuthenticationException('Konto wyłączone.');
        }

        $user = $this->userMirrorSyncer->syncFromMe($data);

        return new SelfValidatingPassport(
            new UserBadge($user->getUserIdentifier(), fn () => $user),
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $this->logger->info('Uwierzytelnianie API tokenem nieudane', [
            'reason' => $exception->getMessage(),
            'path' => $request->getPathInfo(),
        ]);

        return new JsonResponse(['error' => 'Brak autoryzacji.'], Response::HTTP_UNAUTHORIZED);
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return new JsonResponse(['error' => 'Brak autoryzacji.'], Response::HTTP_UNAUTHORIZED);
    }
}
