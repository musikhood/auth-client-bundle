<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Controller;

use Musikhood\AuthClient\Controller\LoginController;
use Musikhood\AuthClient\Controller\LoginMfaController;
use Musikhood\AuthClient\Controller\MfaEnrollmentRequestController;
use Musikhood\AuthClient\Controller\RefreshTokenController;
use Musikhood\AuthClient\Controller\SessionMfaController;
use Musikhood\AuthClient\Http\AuthBackendClient;
use Musikhood\AuthClient\Security\AuthSessionIssuer;
use Musikhood\AuthClient\Tests\Support\JwtTestKit;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

final class MfaControllersTest extends TestCase
{
    private JwtTestKit $jwt;

    protected function setUp(): void
    {
        $this->jwt = new JwtTestKit();
    }

    public function testLoginPlainSuccessUnchanged(): void
    {
        $response = $this->login($this->tokens());

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('[]', $response->getContent());
        self::assertCount(2, $response->headers->getCookies());
    }

    public function testLoginBadCredentialsKeepsMessageAddsCode(): void
    {
        $response = $this->login(new MockResponse('{"error":"x"}', ['http_code' => 401]));

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['error' => 'Nieprawidłowy login lub hasło.', 'code' => 'invalid_credentials'], $this->body($response));
    }

    public function testLoginMfaRequiredPassesThroughWithoutCookies(): void
    {
        $response = $this->login($this->json(401, ['error' => 'Wymagany kod', 'code' => 'mfa_required', 'mfa_token' => 'mt', 'methods' => ['totp', 'recovery']]));

        self::assertSame(401, $response->getStatusCode());
        self::assertSame([], $response->headers->getCookies());
        self::assertSame(['error' => 'Wymagany kod', 'code' => 'mfa_required', 'mfa_token' => 'mt', 'methods' => ['totp', 'recovery']], $this->body($response));
    }

    public function testLoginEnrollmentRequiredPassesThrough(): void
    {
        $response = $this->login($this->json(403, ['error' => 'Skonfiguruj', 'code' => 'mfa_enrollment_required', 'enrollment_url' => 'https://a/setup-2fa?token=x']));

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('mfa_enrollment_required', $this->body($response)['code']);
        self::assertSame('https://a/setup-2fa?token=x', $this->body($response)['enrollment_url']);
    }

    public function testLoginPanelForbiddenUnchanged(): void
    {
        $response = $this->login($this->json(403, ['error' => 'Brak dostępu do panelu.']));

        self::assertSame(['error' => 'Brak dostępu do panelu.'], $this->body($response));
    }

    public function testLoginTooManyAttempts(): void
    {
        $response = $this->login(new MockResponse('{"error":"za dużo","code":"too_many_attempts"}', ['http_code' => 429, 'response_headers' => ['Retry-After: 30']]));

        self::assertSame(429, $response->getStatusCode());
        self::assertSame('30', $response->headers->get('Retry-After'));
        self::assertSame('too_many_attempts', $this->body($response)['code']);
    }

    public function testLoginMfaSuccessSetsCookies(): void
    {
        $controller = new LoginMfaController($this->backend($this->tokens()), $this->issuer(), new NullLogger());
        $response = $controller($this->post(['mfa_token' => 'mt', 'code' => '123456']));

        self::assertSame(200, $response->getStatusCode());
        self::assertCount(2, $response->headers->getCookies());
    }

    public function testLoginMfaInvalidCode(): void
    {
        $controller = new LoginMfaController($this->backend($this->json(401, ['error' => 'Zły kod', 'code' => 'mfa_invalid_code'])), $this->issuer(), new NullLogger());
        $response = $controller($this->post(['mfa_token' => 'mt', 'code' => '000000']));

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['error' => 'Zły kod', 'code' => 'mfa_invalid_code'], $this->body($response));
        self::assertSame([], $response->headers->getCookies());
    }

    public function testLoginMfaPassesReusedCodeThrough(): void
    {
        $controller = new LoginMfaController($this->backend($this->json(401, ['error' => 'Ten kod został już użyty', 'code' => 'mfa_code_reused'])), $this->issuer(), new NullLogger());
        $response = $controller($this->post(['mfa_token' => 'mt', 'code' => '123456']));

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['error' => 'Ten kod został już użyty', 'code' => 'mfa_code_reused'], $this->body($response));
        self::assertSame([], $response->headers->getCookies());
    }

    public function testLoginMfaValidatesInput(): void
    {
        $controller = new LoginMfaController($this->backend(), $this->issuer(), new NullLogger());

        self::assertSame(400, $controller($this->post(['mfa_token' => 'mt']))->getStatusCode());
    }

    public function testSessionMfaUsesRefreshCookieAndNeverClearsOnBadCode(): void
    {
        $controller = new SessionMfaController(
            $this->backend($this->json(401, ['error' => 'Zły kod', 'code' => 'mfa_invalid_code'])),
            $this->issuer(),
            JwtTestKit::cookieFactory(),
            new NullLogger(),
        );
        $request = $this->post(['code' => '000000']);
        $request->cookies->set('refresh_token', 'rt');

        $response = $controller($request);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('mfa_invalid_code', $this->body($response)['code']);
        self::assertSame([], $response->headers->getCookies());
    }

    public function testSessionMfaSuccessAndMissingCookie(): void
    {
        $controller = new SessionMfaController($this->backend($this->tokens()), $this->issuer(), JwtTestKit::cookieFactory(), new NullLogger());
        $request = $this->post(['recovery_code' => 'abcde-fghjk']);
        $request->cookies->set('refresh_token', 'rt');
        self::assertSame(200, $controller($request)->getStatusCode());

        self::assertSame(401, $controller($this->post(['code' => '1']))->getStatusCode());
    }

    public function testEnrollmentRequestForwardsPassword(): void
    {
        $captured = null;
        $http = new MockHttpClient(function (string $method, string $url, array $options) use (&$captured): MockResponse {
            $captured = json_decode((string) $options['body'], true);

            return $this->json(200, ['enrollment_url' => 'https://a/setup-2fa?token=t']);
        });
        $ok = new MfaEnrollmentRequestController(
            new AuthBackendClient($http, new NullLogger(), JwtTestKit::ISSUER, 'cid', 'csecret', 5.0, 10.0),
            JwtTestKit::cookieFactory(),
            new NullLogger(),
        );
        $request = $this->post(['password' => 'secret-pw']);
        $request->cookies->set('refresh_token', 'rt');
        self::assertSame(['enrollment_url' => 'https://a/setup-2fa?token=t'], $this->body($ok($request)));
        self::assertSame(['refresh_token' => 'rt', 'password' => 'secret-pw'], $captured);
    }

    public function testEnrollmentRequestWrongPassword(): void
    {
        $controller = new MfaEnrollmentRequestController($this->backend($this->json(401, ['error' => 'Nieprawidłowy login lub hasło.', 'code' => 'invalid_credentials'])), JwtTestKit::cookieFactory(), new NullLogger());
        $request = $this->post(['password' => 'nope']);
        $request->cookies->set('refresh_token', 'rt');

        $response = $controller($request);
        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_credentials', $this->body($response)['code']);
        self::assertSame([], $response->headers->getCookies(), 'wrong password must not clear the session cookies');
    }

    public function testEnrollmentRequest(): void
    {
        $request = $this->post(['password' => 'pw']);
        $request->cookies->set('refresh_token', 'rt');

        $conflict = new MfaEnrollmentRequestController($this->backend($this->json(409, ['error' => 'x', 'code' => 'mfa_already_enabled'])), JwtTestKit::cookieFactory(), new NullLogger());
        $response = $conflict($request);
        self::assertSame(409, $response->getStatusCode());
        self::assertSame('mfa_already_enabled', $this->body($response)['code']);
    }

    public function testRefreshDeviceMismatchClearsCookiesWithCode(): void
    {
        $controller = new RefreshTokenController($this->backend($this->json(401, ['error' => 'odwołana', 'code' => 'device_mismatch'])), JwtTestKit::cookieFactory(), new NullLogger());
        $request = new Request();
        $request->cookies->set('refresh_token', 'rt');

        $response = $controller($request);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('device_mismatch', $this->body($response)['code']);
        self::assertNotEmpty($response->headers->getCookies());
    }

    private function login(MockResponse $backend): JsonResponse
    {
        $controller = new LoginController($this->backend($backend), $this->issuer(), new NullLogger());

        return $controller($this->post(['username' => 'a@b.pl', 'password' => 'pw']));
    }

    private function issuer(): AuthSessionIssuer
    {
        return new AuthSessionIssuer($this->jwt->validator, JwtTestKit::syncer($this), JwtTestKit::cookieFactory(), new NullLogger());
    }

    private function backend(MockResponse ...$responses): AuthBackendClient
    {
        return new AuthBackendClient(new MockHttpClient($responses), new NullLogger(), JwtTestKit::ISSUER, 'cid', 'csecret', 5.0, 10.0);
    }

    private function tokens(): MockResponse
    {
        return $this->json(200, ['token' => $this->jwt->token(), 'refresh_token' => 'rt2', 'refresh_token_expiration' => time() + 3600]);
    }

    /**
     * @param array<string, mixed> $body
     */
    private function json(int $status, array $body): MockResponse
    {
        return new MockResponse((string) json_encode($body), ['http_code' => $status, 'response_headers' => ['Content-Type: application/json']]);
    }

    /**
     * @param array<string, mixed> $body
     */
    private function post(array $body): Request
    {
        return Request::create('/x', 'POST', server: ['CONTENT_TYPE' => 'application/json'], content: (string) json_encode($body));
    }

    /**
     * @return array<string, mixed>
     */
    private function body(JsonResponse $response): array
    {
        /** @var array<string, mixed> */
        return json_decode((string) $response->getContent(), true);
    }
}
