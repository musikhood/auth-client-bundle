<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Security;

use Musikhood\AuthClient\Cookie\AuthCookieFactory;
use Musikhood\AuthClient\Exception\InvalidJwtException;
use Musikhood\AuthClient\Jwt\JwtClaims;
use Musikhood\AuthClient\Jwt\JwtValidator;
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
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * Uwierzytelnia żądania na podstawie ciasteczka BEARER (JWT z auth servera).
 *
 * Przepływ:
 *   1. Bierzemy ciasteczko BEARER.
 *   2. JwtValidator sprawdza podpis, iss, aud, exp (przez JWKS).
 *   3. Lazy upsert lokalnej kopii użytkownika.
 *   4. Zwracamy Symfony User.
 *
 * Role biorą się z `panel_roles` w JWT (te dla panelu), każda z prefiksem
 * ROLE_. Dzięki temu istniejące #[IsGranted('ROLE_PUBLISH')] działają bez
 * zmian.
 *
 * Przy błędzie zwracamy 401, ale NIE czyścimy ciasteczek. Wygaśnięcie access
 * tokena to typowa rzecz (co ~15 min), refresh_token musi przeżyć żeby front
 * mógł wymienić go na nowy BEARER przez /api/token/refresh.
 */
final class JwtCookieAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    public const ATTR_ACCESS_TOKEN = 'auth_client_jwt';
    public const ATTR_CLAIMS = 'auth_client_claims';

    public function __construct(
        private readonly JwtValidator $jwtValidator,
        private readonly UserMirrorSyncer $userMirrorSyncer,
        private readonly AuthCookieFactory $cookieFactory,
        private readonly LoggerInterface $logger,
    ) {}

    public function supports(Request $request): ?bool
    {
        // Zawsze próbujemy uwierzytelnić. Chcemy 401 na chronionych trasach
        // gdy nie ma ciasteczka, zamiast trybu anonimowego z mylącym 403.
        return null;
    }

    public function authenticate(Request $request): Passport
    {
        $accessToken = $request->cookies->get($this->cookieFactory->accessCookieName());
        if (!is_string($accessToken) || '' === $accessToken) {
            throw new CustomUserMessageAuthenticationException('Brak ciasteczka BEARER');
        }

        try {
            $claims = $this->jwtValidator->validate($accessToken);
        } catch (InvalidJwtException $e) {
            // Token wygasł, zły podpis, niepoprawny issuer itp. Interceptor
            // refreshu po stronie frontu zareaguje na 401 i wymieni
            // refresh_token na nowy BEARER.
            throw new CustomUserMessageAuthenticationException(
                'Walidacja JWT nieudana: ' . $e->getMessage(),
                previous: $e,
            );
        }

        $this->stashContext($request, $accessToken, $claims);

        $user = $this->userMirrorSyncer->upsert($claims);

        // Nie sprawdzamy lokalnego $user->isDisabled() — gating disabled
        // userów leci wyłącznie przez AuthValidationListener, który po
        // udanym /me ustawia świeżą wartość. Lokalne pole służy tylko do
        // wyświetlenia (np. w /api/v1/user/me wystawianym przez paczkę),
        // nigdy do podejmowania decyzji o autoryzacji.

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
        $this->logger->info('Uwierzytelnianie nieudane', [
            'reason' => $exception->getMessage(),
            'path' => $request->getPathInfo(),
        ]);

        // NIE czyścimy tu ciasteczek. Wygaśnięcie access tokena to typowa
        // sytuacja (co ~15 min). Refresh_token musi przeżyć, żeby front mógł
        // wymienić go na nowy BEARER przez /api/token/refresh.
        //
        // Ciasteczka czyścimy tylko świadomie:
        //  1. LogoutController (użytkownik klika wyloguj)
        //  2. RefreshTokenController (refresh definitywnie zawiódł)
        return new JsonResponse(
            ['error' => 'Brak autoryzacji.'],
            Response::HTTP_UNAUTHORIZED,
        );
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        // Stateless API: anonimowe żądanie do chronionego endpointu dostaje
        // 401, nie przekierowanie. Nie czyścimy tu ciasteczek. Użytkownik
        // może być po prostu anonimowy i nie podejmował próby logowania.
        return new JsonResponse(
            ['error' => 'Brak autoryzacji.'],
            Response::HTTP_UNAUTHORIZED,
        );
    }

    /**
     * Udostępnia access token i claimy JWT późniejszym listenerom
     * (głównie AuthValidationListener) przez atrybuty request-u.
     */
    private function stashContext(Request $request, string $accessToken, JwtClaims $claims): void
    {
        $request->attributes->set(self::ATTR_ACCESS_TOKEN, $accessToken);
        $request->attributes->set(self::ATTR_CLAIMS, $claims);
    }
}
