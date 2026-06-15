<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Controller;

use Musikhood\AuthClient\Controller\RefreshTokenController;
use Musikhood\AuthClient\Cookie\AuthCookieFactory;
use Musikhood\AuthClient\Http\AuthBackendClient;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;

/**
 * Make-or-break Fazy 2 (kontrakt czyszczenia ciasteczek):
 *   - 403 (brak dostępu do panelu) → 403, NIGDY nie czyścimy ciasteczek;
 *   - 401 (refresh nieważny) → 401 + wyczyszczone ciasteczka (jedyny przypadek);
 *   - 5xx (master niedostępny) → 503, bez czyszczenia.
 */
final class RefreshTokenControllerTest extends TestCase
{
    private const ACCESS = 'BEARER';
    private const REFRESH = 'refresh_token';

    public function testForbiddenReturns403WithoutClearingCookies(): void
    {
        $response = $this->refresh(new MockResponse(
            (string) json_encode(['error' => 'Brak dostępu do tego panelu.']),
            ['http_code' => 403],
        ));

        self::assertSame(403, $response->getStatusCode());
        // KLUCZOWE: zero Set-Cookie kasujących — sesja na innych panelach żyje.
        self::assertEmpty($response->headers->getCookies(), '403 NIE może czyścić ciasteczek.');
    }

    public function testUnauthorizedReturns401AndClearsCookies(): void
    {
        $response = $this->refresh(new MockResponse('', ['http_code' => 401]));

        self::assertSame(401, $response->getStatusCode());
        // 401 = realna nieważność → cleared cookies (puste, wygasłe).
        $cookies = $response->headers->getCookies();
        self::assertNotEmpty($cookies, '401 MUSI wyczyścić ciasteczka.');
        foreach ($cookies as $cookie) {
            \assert($cookie instanceof Cookie);
            self::assertSame('', (string) $cookie->getValue(), 'Cleared cookie ma pustą wartość.');
        }
    }

    public function testServiceUnavailableReturns503WithoutClearingCookies(): void
    {
        $response = $this->refresh(new MockResponse('', ['http_code' => 503]));

        self::assertSame(503, $response->getStatusCode());
        self::assertEmpty($response->headers->getCookies(), 'Awaria mastera NIE czyści ciasteczek.');
    }

    public function testMissingRefreshCookieReturns401AndClears(): void
    {
        // Brak ciasteczka refresh_token → 401 + clear (jak dziś).
        $controller = $this->controller(new MockHttpClient([]));
        $response = $controller(new Request()); // brak cookies

        self::assertSame(401, $response->getStatusCode());
        self::assertNotEmpty($response->headers->getCookies());
    }

    private function refresh(MockResponse $backendResponse): \Symfony\Component\HttpFoundation\JsonResponse
    {
        $controller = $this->controller(new MockHttpClient([$backendResponse]));

        $request = new Request();
        $request->cookies->set(self::REFRESH, 'rt-value');

        return $controller($request);
    }

    private function controller(MockHttpClient $http): RefreshTokenController
    {
        $backendClient = new AuthBackendClient(
            $http,
            new NullLogger(),
            'https://auth.example',
            'cid',
            'csecret',
            5.0,
            10.0,
        );

        $cookieFactory = new AuthCookieFactory(
            accessCookieName: self::ACCESS,
            refreshCookieName: self::REFRESH,
            cookiePath: '/',
            cookieDomain: null,
            cookieSecure: true,
            cookieHttpOnly: true,
            cookieSameSite: 'none',
        );

        return new RefreshTokenController($backendClient, $cookieFactory, new NullLogger());
    }
}
