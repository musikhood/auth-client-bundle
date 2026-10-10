<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Doctor;

use Musikhood\AuthClient\Cookie\AuthCookieFactory;
use Musikhood\AuthClient\Doctor\AuthDoctor;
use Musikhood\AuthClient\Doctor\CheckResult;
use Musikhood\AuthClient\Doctor\CheckStatus;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Request;

final class AuthDoctorTest extends TestCase
{
    private const PANEL_ID = '0b5d8f6e-6a8f-4a5e-9a0c-1f2e3d4c5b6a';
    private const SECRET = 's3cr3t-value-never-printed';

    protected function setUp(): void
    {
        Request::setTrustedProxies(['10.0.0.0/8'], Request::HEADER_X_FORWARDED_FOR);
    }

    protected function tearDown(): void
    {
        Request::setTrustedProxies([], 0);
    }

    public function testHealthyIntegrationIsAllGreen(): void
    {
        $results = $this->doctor($this->authServer())->run();

        self::assertFalse(AuthDoctor::hasFailures($results), $this->dump($results));
        self::assertSame(CheckStatus::Ok, $this->find($results, 'Dane klienta')->status);
        self::assertSame(CheckStatus::Ok, $this->find($results, 'CORS')->status);
        self::assertSame(CheckStatus::Skipped, $this->find($results, 'panel_id zgodny')->status);
        self::assertStringNotContainsString(self::SECRET, $this->dump($results), 'secrets are never printed');
    }

    public function testWrongClientSecretFails(): void
    {
        $results = $this->doctor($this->authServer(badCredentials: true))->run();

        self::assertTrue(AuthDoctor::hasFailures($results));
        $check = $this->find($results, 'Dane klienta');
        self::assertSame(CheckStatus::Failure, $check->status);
        self::assertStringContainsString('AUTH_CLIENT_SECRET', (string) $check->hint);
    }

    public function testMissingEnvFailsAndSkipsRemoteChecks(): void
    {
        $http = new MockHttpClient(static fn (): MockResponse => throw new \LogicException('no HTTP call expected'));

        $results = $this->doctor($http, ['auth_client.client_secret' => FakeParameters::MISSING_ENV])->run();

        self::assertTrue(AuthDoctor::hasFailures($results));
        $check = $this->find($results, 'Konfiguracja client_secret');
        self::assertSame(CheckStatus::Failure, $check->status);
        self::assertStringContainsString('AUTH_CLIENT_SECRET', (string) $check->detail);
        self::assertSame(CheckStatus::Skipped, $this->find($results, 'Połączenie z auth serverem')->status);
    }

    public function testMissingCorsHeadersFail(): void
    {
        $results = $this->doctor($this->authServer(), [
            'nelmio_cors.defaults' => ['allow_credentials' => false, 'allow_headers' => ['content-type'], 'expose_headers' => [], 'allow_origin' => ['^https://panel\.example$']],
        ])->run();

        $check = $this->find($results, 'CORS');
        self::assertSame(CheckStatus::Failure, $check->status);
        self::assertStringContainsString('X-Device-Fp', (string) $check->detail);
        self::assertStringContainsString('Retry-After', (string) $check->detail);
        self::assertStringContainsString('allow_credentials', (string) $check->detail);
    }

    public function testNoNelmioIsOnlyAWarning(): void
    {
        $results = $this->doctor($this->authServer(), ['nelmio_cors.defaults' => null])->run();

        self::assertSame(CheckStatus::Warning, $this->find($results, 'CORS')->status);
        self::assertFalse(AuthDoctor::hasFailures($results));
    }

    public function testUncoveredPublicRoutesFail(): void
    {
        $results = $this->doctor($this->authServer(), [], new FakeSecurityInspector(publicRoutesCovered: false))->run();

        $check = $this->find($results, 'Trasy publiczne');
        self::assertSame(CheckStatus::Failure, $check->status);
        self::assertStringContainsString('/api/session/mfa', (string) $check->detail);
    }

    public function testAccessTokenDetectsPanelMismatch(): void
    {
        $results = $this->doctor($this->authServer(introspectedPanelId: '11111111-1111-4111-8111-111111111111'))->run('jwt');

        self::assertSame(CheckStatus::Failure, $this->find($results, 'panel_id zgodny')->status);

        $ok = $this->doctor($this->authServer(introspectedPanelId: self::PANEL_ID))->run('jwt');
        self::assertSame(CheckStatus::Ok, $this->find($ok, 'panel_id zgodny')->status);
    }

    public function testOldAuthServerWithout2faRoutesFails(): void
    {
        $results = $this->doctor($this->authServer(without2fa: true))->run();

        self::assertSame(CheckStatus::Failure, $this->find($results, 'obsługuje 2FA')->status);
    }

    public function testUnreachableAuthServerFails(): void
    {
        $http = new MockHttpClient(static fn (): MockResponse => new MockResponse('', ['error' => 'Could not resolve host']));

        $results = $this->doctor($http)->run();

        self::assertSame(CheckStatus::Failure, $this->find($results, 'JWKS')->status);
        self::assertSame(CheckStatus::Skipped, $this->find($results, 'Dane klienta')->status);
    }

    public function testSameSiteNoneWithoutSecureIsAWarning(): void
    {
        $cookies = new AuthCookieFactory('BEARER', 'refresh_token', '/', null, false, true, 'none');

        $results = $this->doctor($this->authServer(), [], null, $cookies)->run();

        $check = $this->find($results, 'Ciasteczka');
        self::assertSame(CheckStatus::Warning, $check->status);
        self::assertStringContainsString('odrzuci', (string) $check->detail);
        self::assertFalse(AuthDoctor::hasFailures($results));
    }

    public function testSameSiteNoneOnTheSameDomainSuggestsLax(): void
    {
        $none = new AuthCookieFactory('BEARER', 'refresh_token', '/', '.vitkac.com', true, true, 'none');
        $cors = ['nelmio_cors.defaults' => [
            'allow_credentials' => true,
            'allow_origin' => ['^https://pim\\.vitkac\\.com$'],
            'allow_headers' => ['x-device-fp'],
            'expose_headers' => ['retry-after'],
        ]];

        $check = $this->find($this->doctor($this->authServer(), $cors, null, $none)->run(), 'Ciasteczka');
        self::assertSame(CheckStatus::Ok, $check->status);
        self::assertStringContainsString('lax wystarczy', (string) $check->hint);

        // Front on another domain → none is justified, no hint.
        $cors['nelmio_cors.defaults']['allow_origin'] = ['^https://panel\\.other\\.com$'];
        self::assertNull($this->find($this->doctor($this->authServer(), $cors, null, $none)->run(), 'Ciasteczka')->hint);

        // Origin given as a real regex → front host unknown → no hint.
        $cors['nelmio_cors.defaults']['allow_origin'] = ['^https?://(pim|ai)\\.vitkac\\.com$'];
        self::assertNull($this->find($this->doctor($this->authServer(), $cors, null, $none)->run(), 'Ciasteczka')->hint);

        // API host from framework.router.default_uri when no cookie domain is set.
        $hostOnly = new AuthCookieFactory('BEARER', 'refresh_token', '/', null, true, true, 'none');
        $cors['nelmio_cors.defaults']['allow_origin'] = ['https://pim.vitkac.com'];
        $withRouter = $cors + ['router.request_context.host' => 'pim-api.vitkac.com'];
        self::assertNotNull($this->find($this->doctor($this->authServer(), $withRouter, null, $hostOnly)->run(), 'Ciasteczka')->hint);
        self::assertNull($this->find($this->doctor($this->authServer(), $cors + ['router.request_context.host' => 'localhost'], null, $hostOnly)->run(), 'Ciasteczka')->hint);
    }

    public function testDefaultLaxNeedsNoHint(): void
    {
        $lax = new AuthCookieFactory('BEARER', 'refresh_token', '/', null, true, true, 'lax');

        $check = $this->find($this->doctor($this->authServer(), [], null, $lax)->run(), 'Ciasteczka');

        self::assertSame(CheckStatus::Ok, $check->status);
        self::assertNull($check->hint);
    }

    public function testMissingTrustedProxiesIsAWarning(): void
    {
        Request::setTrustedProxies([], 0);

        $results = $this->doctor($this->authServer())->run();

        self::assertSame(CheckStatus::Warning, $this->find($results, 'Trusted proxies')->status);
    }

    private function authServer(bool $badCredentials = false, bool $without2fa = false, ?string $introspectedPanelId = null): MockHttpClient
    {
        return new MockHttpClient(static function (string $method, string $url, array $options) use ($badCredentials, $without2fa, $introspectedPanelId): MockResponse {
            $path = (string) parse_url($url, \PHP_URL_PATH);
            $body = (string) ($options['body'] ?? '');

            return match (true) {
                '/.well-known/jwks.json' === $path => new MockResponse('{"keys":[{"kid":"k"}]}'),
                '/api/auth/backend/introspect' === $path && $badCredentials => new MockResponse('{"error":"Nieprawidłowe dane klienta backendowego."}', ['http_code' => 401, 'response_headers' => ['WWW-Authenticate' => 'Basic realm="Backend client"']]),
                '/api/auth/backend/introspect' === $path && str_contains($body, '"token"') => new MockResponse(json_encode(['panelId' => $introspectedPanelId], \JSON_THROW_ON_ERROR)),
                '/api/auth/backend/introspect' === $path => new MockResponse('{"error":"Nie przekazano tokenu."}', ['http_code' => 401]),
                '/api/auth/backend/login/mfa' === $path => new MockResponse('{}', ['http_code' => $without2fa ? 404 : 401]),
                default => new MockResponse('', ['http_code' => 404]),
            };
        }, 'https://auth.example');
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function doctor(MockHttpClient $http, array $parameters = [], ?FakeSecurityInspector $inspector = null, ?AuthCookieFactory $cookies = null): AuthDoctor
    {
        $values = array_merge([
            'auth_client.base_url' => 'https://auth.example',
            'auth_client.panel_id' => self::PANEL_ID,
            'auth_client.client_id' => 'pim-backend',
            'auth_client.client_secret' => self::SECRET,
            'nelmio_cors.defaults' => [
                'allow_credentials' => true,
                'allow_origin' => ['^https://panel\.example$'],
                'allow_headers' => ['content-type', 'x-device-fp'],
                'expose_headers' => ['retry-after'],
            ],
            'nelmio_cors.map' => ['^/' => []],
        ], $parameters);
        $values = array_filter($values, static fn (mixed $v): bool => null !== $v);

        return new AuthDoctor(
            new FakeParameters($values),
            $http,
            $inspector ?? new FakeSecurityInspector(),
            $cookies ?? new AuthCookieFactory('BEARER', 'refresh_token', '/', '.example', true, true, 'none'),
            new NullLogger(),
        );
    }

    /**
     * @param list<CheckResult> $results
     */
    private function find(array $results, string $labelPart): CheckResult
    {
        foreach ($results as $result) {
            if (str_contains($result->label, $labelPart)) {
                return $result;
            }
        }
        self::fail(sprintf('No check "%s" in: %s', $labelPart, $this->dump($results)));
    }

    /**
     * @param list<CheckResult> $results
     */
    private function dump(array $results): string
    {
        return implode("\n", array_map(static fn (CheckResult $r): string => sprintf('[%s] %s — %s | %s', $r->status->value, $r->label, $r->detail, $r->hint), $results));
    }
}
