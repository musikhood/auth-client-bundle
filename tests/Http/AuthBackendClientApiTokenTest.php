<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Http;

use Musikhood\AuthClient\Exception\AuthBackendException;
use Musikhood\AuthClient\Http\AuthBackendClient;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Ramsey\Uuid\Uuid;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class AuthBackendClientApiTokenTest extends TestCase
{
    public function testIntrospectValidTokenReturnsUserData(): void
    {
        $panelId = Uuid::uuid4()->toString();
        $payload = [
            'id' => Uuid::uuid4()->toString(),
            'email' => 'u@example.com',
            'displayName' => 'Jan',
            'roles' => ['ROLE_ADMIN'],
            'panelId' => $panelId,
            'panelName' => 'editor-prod',
            'panelRoles' => ['PUBLISH', 'EDIT'],
            'disabled' => false,
        ];
        $http = new MockHttpClient([new MockResponse((string) json_encode($payload), ['http_code' => 200])]);

        $data = $this->client($http)->introspectApiToken('mhpat_good');

        self::assertNotNull($data);
        self::assertSame('u@example.com', $data->email);
        self::assertSame($panelId, $data->panelId?->toString());
        self::assertSame(['PUBLISH', 'EDIT'], $data->panelRoles);
        self::assertFalse($data->disabled);
    }

    public function testIntrospectUnauthorizedReturnsNull(): void
    {
        $http = new MockHttpClient([new MockResponse('', ['http_code' => 401])]);

        self::assertNull($this->client($http)->introspectApiToken('mhpat_bad'));
    }

    public function testIntrospectServerErrorThrows(): void
    {
        $http = new MockHttpClient([new MockResponse('', ['http_code' => 502])]);

        $this->expectException(AuthBackendException::class);
        $this->client($http)->introspectApiToken('mhpat_x');
    }

    public function testIntrospectSendsBasicAuthAndTokenHeader(): void
    {
        $captured = null;
        $http = new MockHttpClient(function (string $method, string $url, array $options) use (&$captured): MockResponse {
            $captured = ['method' => $method, 'url' => $url, 'options' => $options];

            return new MockResponse((string) json_encode([
                'id' => Uuid::uuid4()->toString(),
                'email' => 'u@example.com',
                'roles' => [],
                'panelId' => Uuid::uuid4()->toString(),
            ]), ['http_code' => 200]);
        });

        $this->client($http)->introspectApiToken('mhpat_secret');

        self::assertNotNull($captured);
        self::assertSame('POST', $captured['method']);
        self::assertStringEndsWith('/api/auth/backend/api-token/verify', $captured['url']);
        self::assertContains('X-Api-Token: mhpat_secret', $captured['options']['headers']);
        self::assertContains('Authorization: Basic ' . base64_encode('cid:csecret'), $captured['options']['headers']);
    }

    private function client(MockHttpClient $http): AuthBackendClient
    {
        return new AuthBackendClient(
            $http,
            new NullLogger(),
            'https://auth.example',
            'cid',
            'csecret',
            5.0,
            10.0,
        );
    }
}
