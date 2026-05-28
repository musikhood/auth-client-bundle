<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Jwt;

use Firebase\JWT\JWT;
use Musikhood\AuthClient\Exception\InvalidJwtException;
use Musikhood\AuthClient\Jwt\WebhookJwtValidator;
use Musikhood\AuthClient\Tests\Support\JwksTestFactory;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Ramsey\Uuid\Uuid;

/**
 * Verify-only walidacja webhook JWT od auth servera. Prawdziwy RSA keypair +
 * JWT::encode/decode (firebase/php-jwt) dla wiernej reprezentacji prod tokenu.
 * Pokrywa happy path, signature, iss, aud, expired, brak sub/ver, nieznany
 * reason (forward-compat).
 */
final class WebhookJwtValidatorTest extends TestCase
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

    public function testValidateHappyPath(): void
    {
        $userId = Uuid::uuid4();
        $panelRemoved = Uuid::uuid4()->toString();
        $token = $this->encode([
            'iss' => self::ISSUER,
            'aud' => self::PANEL_ID,
            'sub' => $userId->toString(),
            'reason' => 'disabled',
            'panel_id' => $panelRemoved,
            'ver' => 7,
            'iat' => time(),
            'exp' => time() + 60,
        ]);

        $claims = $this->validator()->validate($token);

        self::assertSame((string) $userId, $claims->userId->toString());
        self::assertSame('disabled', $claims->reason);
        self::assertSame($panelRemoved, $claims->panelId);
        self::assertSame(7, $claims->tokenVersion);
    }

    public function testValidateAcceptsNullPanelId(): void
    {
        $token = $this->encode($this->basePayload(['panel_id' => null]));

        $claims = $this->validator()->validate($token);

        self::assertNull($claims->panelId);
    }

    public function testValidateAcceptsUnknownReasonForwardCompat(): void
    {
        $token = $this->encode($this->basePayload(['reason' => 'some_future_reason']));

        $claims = $this->validator()->validate($token);

        self::assertSame('some_future_reason', $claims->reason);
    }

    public function testValidateThrowsOnSignatureInvalid(): void
    {
        // Token podpisany naszym kluczem, ale JWKS serwuje INNY klucz publiczny
        // → weryfikacja podpisu firebase/php-jwt failuje.
        $token = $this->encode($this->basePayload());

        $other = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($other);
        $otherDetails = openssl_pkey_get_details($other);
        self::assertNotFalse($otherDetails);
        $wrongPublicKeyPem = $otherDetails['key'];

        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessage('Niepoprawny podpis');
        $this->validator($wrongPublicKeyPem)->validate($token);
    }

    public function testValidateThrowsOnIssuerMismatch(): void
    {
        $token = $this->encode($this->basePayload(['iss' => 'https://wrong.example']));

        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessageMatches('/issuer/i');
        $this->validator()->validate($token);
    }

    public function testValidateThrowsOnAudienceMismatch(): void
    {
        // aud = UUID innego panelu (lub 'mirror') → webhook nie dla nas → odrzucony.
        $token = $this->encode($this->basePayload(['aud' => Uuid::uuid4()->toString()]));

        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessageMatches('/audience/i');
        $this->validator()->validate($token);
    }

    public function testValidateThrowsOnExpiredToken(): void
    {
        $token = $this->encode($this->basePayload([
            'iat' => time() - 3600,
            'exp' => time() - 60,
        ]));

        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessage('Token wygasł');
        $this->validator()->validate($token);
    }

    public function testValidateThrowsOnMissingSub(): void
    {
        $payload = $this->basePayload();
        unset($payload['sub']);

        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessageMatches('/sub/');
        $this->validator()->validate($this->encode($payload));
    }

    public function testValidateThrowsOnMissingVer(): void
    {
        $payload = $this->basePayload();
        unset($payload['ver']);

        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessageMatches('/ver/');
        $this->validator()->validate($this->encode($payload));
    }

    public function testValidateThrowsOnNonUuidSub(): void
    {
        $token = $this->encode($this->basePayload(['sub' => 'not-a-uuid']));

        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessageMatches('/UUID/');
        $this->validator()->validate($token);
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private function basePayload(array $overrides = []): array
    {
        return array_merge([
            'iss' => self::ISSUER,
            'aud' => self::PANEL_ID,
            'sub' => Uuid::uuid4()->toString(),
            'reason' => 'disabled',
            'panel_id' => Uuid::uuid4()->toString(),
            'ver' => 1,
            'iat' => time(),
            'exp' => time() + 60,
        ], $overrides);
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function encode(array $payload): string
    {
        return JWT::encode($payload, $this->privateKey, 'RS256', self::KID);
    }

    private function validator(?string $jwksPublicKeyPem = null): WebhookJwtValidator
    {
        $jwks = JwksTestFactory::withKey($jwksPublicKeyPem ?? $this->publicKeyPem, self::KID, self::ISSUER);

        return new WebhookJwtValidator($jwks, new NullLogger(), self::ISSUER, self::PANEL_ID);
    }
}
