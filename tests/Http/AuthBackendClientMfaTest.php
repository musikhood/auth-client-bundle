<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Http;

use Musikhood\AuthClient\Exception\AuthBackendDeviceMismatchException;
use Musikhood\AuthClient\Exception\AuthBackendForbiddenException;
use Musikhood\AuthClient\Exception\AuthBackendMfaAlreadyEnabledException;
use Musikhood\AuthClient\Exception\AuthBackendMfaEnrollmentRequiredException;
use Musikhood\AuthClient\Exception\AuthBackendMfaInvalidCodeException;
use Musikhood\AuthClient\Exception\AuthBackendMfaRequiredException;
use Musikhood\AuthClient\Exception\AuthBackendMfaStepUpException;
use Musikhood\AuthClient\Exception\AuthBackendTooManyAttemptsException;
use Musikhood\AuthClient\Exception\AuthBackendUnauthorizedException;
use Musikhood\AuthClient\Http\AuthBackendClient;
use Musikhood\AuthClient\Http\ClientContextProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

final class AuthBackendClientMfaTest extends TestCase
{
    private const TOKENS = ['token' => 'jwt', 'refresh_token' => 'rt', 'refresh_token_expiration' => 1999999999];

    public function testLoginWithoutCodeKeeps06Behaviour(): void
    {
        $this->expectException(AuthBackendUnauthorizedException::class);
        $this->client(new MockResponse('{"error":"x"}', ['http_code' => 401]))->login('a@b.pl', 'pw');
    }

    public function testMfaRequiredCarriesTokenAndIsUnauthorizedSubclass(): void
    {
        try {
            $this->client($this->json(401, ['error' => 'Wymagany kod', 'code' => 'mfa_required', 'mfa_token' => 't1', 'methods' => ['totp', 'recovery']]))
                ->login('a@b.pl', 'pw');
            self::fail('expected exception');
        } catch (AuthBackendMfaRequiredException $e) {
            self::assertInstanceOf(AuthBackendUnauthorizedException::class, $e);
            self::assertSame('t1', $e->mfaToken);
            self::assertSame(['totp', 'recovery'], $e->methods);
            self::assertSame('Wymagany kod', $e->getMessage());
        }
    }

    public function testEnrollmentRequiredCarriesUrlAndIsForbiddenSubclass(): void
    {
        try {
            $this->client($this->json(403, ['error' => 'Skonfiguruj', 'code' => 'mfa_enrollment_required', 'enrollment_url' => 'https://a/setup-2fa?token=x']))
                ->login('a@b.pl', 'pw');
            self::fail('expected exception');
        } catch (AuthBackendMfaEnrollmentRequiredException $e) {
            self::assertInstanceOf(AuthBackendForbiddenException::class, $e);
            self::assertSame('https://a/setup-2fa?token=x', $e->enrollmentUrl);
        }
    }

    public function testIntrospectStepUp(): void
    {
        $this->expectException(AuthBackendMfaStepUpException::class);
        $this->client($this->json(403, ['error' => 'x', 'code' => 'mfa_step_up']))->introspectJwt('jwt');
    }

    public function testTooManyAttemptsWithRetryAfter(): void
    {
        try {
            $this->client(new MockResponse('{"error":"za dużo","code":"too_many_attempts"}', ['http_code' => 429, 'response_headers' => ['Retry-After: 90']]))
                ->login('a@b.pl', 'pw');
            self::fail('expected exception');
        } catch (AuthBackendTooManyAttemptsException $e) {
            self::assertSame(90, $e->retryAfter);
        }
    }

    public function testMfaCodesMapping(): void
    {
        foreach ([
            'mfa_invalid_code' => AuthBackendMfaInvalidCodeException::class,
            'invalid_credentials' => \Musikhood\AuthClient\Exception\AuthBackendInvalidCredentialsException::class,
            'device_mismatch' => AuthBackendDeviceMismatchException::class,
        ] as $code => $class) {
            try {
                $this->client($this->json(401, ['error' => 'x', 'code' => $code]))->loginMfa('t', '123456', null);
                self::fail($code);
            } catch (AuthBackendUnauthorizedException $e) {
                self::assertInstanceOf($class, $e);
            }
        }

        $this->expectException(AuthBackendMfaAlreadyEnabledException::class);
        $this->client($this->json(409, ['error' => 'x', 'code' => 'mfa_already_enabled']))->requestMfaEnrollment('rt', 'pw');
    }

    public function testReusedCodeKeepsItsCode(): void
    {
        try {
            $this->client($this->json(401, ['error' => 'Ten kod został już użyty', 'code' => 'mfa_code_reused']))->loginMfa('t', '123456', null);
            self::fail('expected exception');
        } catch (AuthBackendMfaInvalidCodeException $e) {
            self::assertTrue($e->isReused());
            self::assertSame('mfa_code_reused', $e->errorCode);
            self::assertSame('Ten kod został już użyty', $e->getMessage());
        }

        try {
            $this->client($this->json(401, ['error' => 'x', 'code' => 'mfa_invalid_code']))->loginMfa('t', '000000', null);
            self::fail('expected exception');
        } catch (AuthBackendMfaInvalidCodeException $e) {
            self::assertFalse($e->isReused());
        }
    }

    public function testForwardsEndUserContextAndDevice(): void
    {
        $captured = [];
        $http = new MockHttpClient(function (string $method, string $url, array $options) use (&$captured): MockResponse {
            $captured[] = ['url' => $url, 'options' => $options];

            return $this->json(200, self::TOKENS);
        });

        $browser = Request::create('/api/login/mfa', 'POST', server: [
            'REMOTE_ADDR' => '81.2.69.160',
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
            'HTTP_X_DEVICE_FP' => str_repeat('a', 64),
            'CONTENT_TYPE' => 'application/json',
        ], content: '{"device":{"os":"macOS"}}');
        $stack = new RequestStack();
        $stack->push($browser);

        $client = new AuthBackendClient($http, new NullLogger(), 'https://auth.example', 'cid', 'csecret', 5.0, 10.0, new ClientContextProvider($stack));
        $client->loginMfa('t1', '123456', null, true);
        $client->refresh('rt');

        $headers = implode("\n", $captured[0]['options']['headers']);
        self::assertStringContainsString('X-Client-Ip: 81.2.69.160', $headers);
        self::assertStringContainsString('X-Client-User-Agent: Mozilla/5.0', $headers);
        self::assertStringContainsString('X-Device-Fp: ' . str_repeat('a', 64), $headers);
        $body = json_decode((string) $captured[0]['options']['body'], true);
        self::assertSame(['mfa_token' => 't1', 'code' => '123456', 'remember_device' => true, 'device' => ['os' => 'macOS']], $body);
        self::assertStringEndsWith('/api/auth/backend/login/mfa', $captured[0]['url']);

        // refresh forwards the device from the browser body too.
        self::assertSame(['refresh_token' => 'rt', 'device' => ['os' => 'macOS']], json_decode((string) $captured[1]['options']['body'], true));
    }

    public function testNoRequestStackMeansNoExtraHeaders(): void
    {
        $captured = ['body' => '', 'headers' => []];
        $http = new MockHttpClient(function (string $method, string $url, array $options) use (&$captured): MockResponse {
            $captured = $options;

            return $this->json(200, self::TOKENS);
        });

        (new AuthBackendClient($http, new NullLogger(), 'https://auth.example', 'cid', 'csecret', 5.0, 10.0))->login('a@b.pl', 'pw');

        self::assertSame(['email' => 'a@b.pl', 'password' => 'pw'], json_decode((string) $captured['body'], true));
        self::assertStringNotContainsString('X-Client-Ip', implode("\n", $captured['headers']));
    }

    /**
     * @param array<string, mixed> $body
     */
    private function json(int $status, array $body): MockResponse
    {
        return new MockResponse((string) json_encode($body), ['http_code' => $status, 'response_headers' => ['Content-Type: application/json']]);
    }

    private function client(MockResponse $response): AuthBackendClient
    {
        return new AuthBackendClient(new MockHttpClient([$response]), new NullLogger(), 'https://auth.example', 'cid', 'csecret', 5.0, 10.0);
    }
}
