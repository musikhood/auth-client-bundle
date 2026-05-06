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
 */
final readonly class AuthCookieFactory
{
    public function __construct(
        private string $accessCookieName,
        private string $refreshCookieName,
        private string $cookiePath,
        private bool $cookieSecure,
        private bool $cookieHttpOnly,
        private string $cookieSameSite,
        private int $cookieLifetime,
    ) {}

    public function applyTokens(Response $response, TokenPair $tokens): void
    {
        $expiresAt = time() + $this->cookieLifetime;

        $response->headers->setCookie($this->buildCookie(
            name: $this->accessCookieName,
            value: $tokens->accessToken,
            expiresAt: $expiresAt,
        ));
        $response->headers->setCookie($this->buildCookie(
            name: $this->refreshCookieName,
            value: $tokens->refreshToken,
            expiresAt: $expiresAt,
        ));
    }

    public function clear(Response $response): void
    {
        $sameSite = $this->normalizeSameSite();

        $response->headers->clearCookie(
            name: $this->accessCookieName,
            path: $this->cookiePath,
            secure: $this->cookieSecure,
            httpOnly: $this->cookieHttpOnly,
            sameSite: $sameSite,
        );
        $response->headers->clearCookie(
            name: $this->refreshCookieName,
            path: $this->cookiePath,
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
            domain: null,
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
