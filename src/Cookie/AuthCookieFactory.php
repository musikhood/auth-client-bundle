<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Cookie;

use Musikhood\AuthClient\Dto\TokenPair;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;

/**
 * Tworzy i ustawia w odpowiedzi ciasteczka HttpOnly z JWT i refresh tokenem.
 *
 * Ciasteczko z JWT nazywa się `BEARER`, z refresh tokenem `refresh_token`.
 * Tak samo jak ustawia je sam auth server (lexik + gesdinet). Dzięki temu
 * front, który gada wprost z auth serverem, działa też z każdym backendem
 * używającym tego modułu bez żadnych zmian.
 *
 * Tokeny nigdy nie wychodzą poza ciasteczka. Front widzi tylko
 * `withCredentials`, nigdy samego JWT.
 *
 * TTL ciasteczek jest hardcoded w paczce, bo i tak ostatecznym źródłem prawdy
 * jest auth server (`JWT_TTL` i `REFRESH_TOKEN_TTL` w jego env). Trzymamy je
 * tu zsynchronizowane ze standardowym deploymentem auth servera, żeby browser
 * nie musiał wozić martwych ciasteczek znacznie dłużej niż ich payload jest
 * ważny. Jeśli auth server zmieni TTL — wartości tu trzeba podbumpować i
 * wydać nową wersję paczki.
 */
final readonly class AuthCookieFactory
{
    /** Czas życia ciasteczka BEARER (sekundy). Spójne z JWT_TTL na auth serverze. */
    private const ACCESS_COOKIE_LIFETIME_SECONDS = 900;

    /** Czas życia ciasteczka refresh_token (sekundy). Spójne z REFRESH_TOKEN_TTL na auth serverze. */
    private const REFRESH_COOKIE_LIFETIME_SECONDS = 2592000;

    public function __construct(
        private string $accessCookieName,
        private string $refreshCookieName,
        private string $cookiePath,
        private ?string $cookieDomain,
        private bool $cookieSecure,
        private bool $cookieHttpOnly,
        private string $cookieSameSite,
    ) {}

    public function applyTokens(Response $response, TokenPair $tokens): void
    {
        $now = time();

        $response->headers->setCookie($this->buildCookie(
            name: $this->accessCookieName,
            value: $tokens->accessToken,
            expiresAt: $now + self::ACCESS_COOKIE_LIFETIME_SECONDS,
        ));
        $response->headers->setCookie($this->buildCookie(
            name: $this->refreshCookieName,
            value: $tokens->refreshToken,
            expiresAt: $now + self::REFRESH_COOKIE_LIFETIME_SECONDS,
        ));
    }

    public function clear(Response $response): void
    {
        $sameSite = $this->normalizeSameSite();

        $response->headers->clearCookie(
            name: $this->accessCookieName,
            path: $this->cookiePath,
            domain: $this->cookieDomain,
            secure: $this->cookieSecure,
            httpOnly: $this->cookieHttpOnly,
            sameSite: $sameSite,
        );
        $response->headers->clearCookie(
            name: $this->refreshCookieName,
            path: $this->cookiePath,
            domain: $this->cookieDomain,
            secure: $this->cookieSecure,
            httpOnly: $this->cookieHttpOnly,
            sameSite: $sameSite,
        );
    }

    public function accessCookieName(): string
    {
        return $this->accessCookieName;
    }

    public function refreshCookieName(): string
    {
        return $this->refreshCookieName;
    }

    private function buildCookie(string $name, string $value, int $expiresAt): Cookie
    {
        return Cookie::create(
            name: $name,
            value: $value,
            expire: $expiresAt,
            path: $this->cookiePath,
            domain: $this->cookieDomain,
            secure: $this->cookieSecure,
            httpOnly: $this->cookieHttpOnly,
            raw: false,
            sameSite: $this->normalizeSameSite(),
        );
    }

    /** @return 'lax'|'strict'|'none'|null */
    private function normalizeSameSite(): ?string
    {
        return match (strtolower($this->cookieSameSite)) {
            'lax' => Cookie::SAMESITE_LAX,
            'strict' => Cookie::SAMESITE_STRICT,
            'none' => Cookie::SAMESITE_NONE,
            default => null,
        };
    }
}
