<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Controller;

use Firebase\JWT\JWT;
use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Musikhood\AuthClient\Controller\WebhookController;
use Musikhood\AuthClient\EventListener\AuthValidationListener;
use Musikhood\AuthClient\Http\AuthBackendClient;
use Musikhood\AuthClient\Jwt\WebhookJwtValidator;
use Musikhood\AuthClient\Security\UserMirrorSyncer;
use Musikhood\AuthClient\Security\UserTokenVersionStore;
use Musikhood\AuthClient\Tests\Support\JwksTestFactory;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\NullLogger;
use Ramsey\Uuid\Uuid;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Endpoint webhooka inwalidacji (strona konsumenta). Używa prawdziwych
 * collaboratorów (validator z mockiem JwksProvider + realny podpis, store +
 * listener z mockiem cache), bo final readonly klas nie da się mockować — przy
 * okazji to szczelny test integracji validator↔controller↔cache.
 */
final class WebhookControllerTest extends TestCase
{
    private const ISSUER = 'https://auth.example';
    private const PANEL_ID = 'b1d1c0de-0000-4000-8000-000000000001';
    private const KID = 'test-kid';

    private string $privateKey;
    private string $publicKeyPem;

    protected function setUp(): void
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($resource);
        openssl_pkey_export($resource, $privateKey);
        $details = openssl_pkey_get_details($resource);
        self::assertNotFalse($details);

        $this->privateKey = $privateKey;
        $this->publicKeyPem = $details['key'];
    }

    public function testValidWebhookSavesVersionAndInvalidatesValidatedCache(): void
    {
        $userId = Uuid::uuid4();
        $token = $this->encode([
            'iss' => self::ISSUER,
            'aud' => self::PANEL_ID,
            'sub' => $userId->toString(),
            'reason' => 'disabled',
            'panel_id' => null,
            'ver' => 9,
            'iat' => time(),
            'exp' => time() + 60,
        ]);

        $tokenVersionItem = $this->createMock(CacheItemInterface::class);
        $tokenVersionItem->method('set')->willReturnSelf();
        $tokenVersionItem->method('expiresAfter')->willReturnSelf();

        $cache = $this->createMock(CacheItemPoolInterface::class);
        // store->save → getItem(auth_client_token_version_<id>) + save(item)
        $cache->expects(self::once())
            ->method('getItem')
            ->with('auth_client_token_version_' . $userId->toString())
            ->willReturn($tokenVersionItem);
        $cache->expects(self::once())->method('save')->with($tokenVersionItem);
        // listener->invalidateValidatedCache → deleteItem(auth_client_validated_<id>)
        $cache->expects(self::once())
            ->method('deleteItem')
            ->with('auth_client_validated_' . $userId->toString());

        $response = $this->controller($cache)->__invoke($this->request($token));

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertSame('{"ok":true}', $response->getContent());
    }

    public function testMissingBearerReturns401(): void
    {
        $cache = $this->createMock(CacheItemPoolInterface::class);
        $cache->expects(self::never())->method('save');
        $cache->expects(self::never())->method('deleteItem');

        $response = $this->controller($cache)->__invoke(new Request());

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }

    public function testInvalidJwtReturns401(): void
    {
        // Podpisany INNYM kluczem → signature invalid → 401, brak efektów ubocznych.
        $other = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($other);
        openssl_pkey_export($other, $otherPrivate);
        $token = JWT::encode($this->validPayload(), $otherPrivate, 'RS256', self::KID);

        $cache = $this->createMock(CacheItemPoolInterface::class);
        $cache->expects(self::never())->method('save');
        $cache->expects(self::never())->method('deleteItem');

        $response = $this->controller($cache)->__invoke($this->request($token));

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }

    /**
     * @return array<string, mixed>
     */
    private function validPayload(): array
    {
        return [
            'iss' => self::ISSUER,
            'aud' => self::PANEL_ID,
            'sub' => Uuid::uuid4()->toString(),
            'reason' => 'disabled',
            'panel_id' => null,
            'ver' => 1,
            'iat' => time(),
            'exp' => time() + 60,
        ];
    }

    private function controller(CacheItemPoolInterface $cache): WebhookController
    {
        $jwks = JwksTestFactory::withKey($this->publicKeyPem, self::KID, self::ISSUER);
        $validator = new WebhookJwtValidator($jwks, new NullLogger(), self::ISSUER, self::PANEL_ID);

        $store = new UserTokenVersionStore($cache);

        // AuthValidationListener jest final readonly — budujemy realnie z mockami
        // jego zależności. W przepływie webhooka dotykamy tylko
        // invalidateValidatedCache() → cache->deleteItem().
        $backendClient = new AuthBackendClient(
            $this->createMock(HttpClientInterface::class),
            new NullLogger(),
            self::ISSUER,
            'client-id',
            'client-secret',
            5.0,
            10.0,
        );
        $mirrorSyncer = new UserMirrorSyncer($this->createMock(PanelUserRepositoryInterface::class));
        $listener = new AuthValidationListener(
            $backendClient,
            $mirrorSyncer,
            $cache,
            new NullLogger(),
            30,
            3,
            60,
        );

        return new WebhookController($validator, $store, $listener, new NullLogger());
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function encode(array $payload): string
    {
        return JWT::encode($payload, $this->privateKey, 'RS256', self::KID);
    }

    private function request(string $token): Request
    {
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $token);

        return $request;
    }
}
