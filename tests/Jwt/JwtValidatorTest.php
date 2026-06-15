<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Jwt;

use Firebase\JWT\JWT;
use Musikhood\AuthClient\Exception\InvalidJwtException;
use Musikhood\AuthClient\Jwt\JwtValidator;
use Musikhood\AuthClient\Tests\Support\JwksTestFactory;
use PHPUnit\Framework\TestCase;
use Ramsey\Uuid\Uuid;

/**
 * Walidacja access-token JWT (ścieżka cookie/SSO). PANEL-AGNOSTYCZNA:
 *   - NIE walidujemy `aud` (token z dowolnym/brakującym aud przechodzi),
 *   - `panel_id` jest OPCJONALNY,
 *   - walidujemy: podpis (JWKS), `iss`, `exp`.
 * Prawdziwy RSA keypair + firebase/php-jwt dla wiernej reprezentacji.
 */
final class JwtValidatorTest extends TestCase
{
    private const ISSUER = 'https://auth.example';
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

    public function testValidateHappyPathWithPanelId(): void
    {
        $userId = Uuid::uuid4();
        $panelId = Uuid::uuid4()->toString();
        $token = $this->encode([
            'iss' => self::ISSUER,
            'aud' => $panelId,
            'user_id' => $userId->toString(),
            'email' => 'jan@example.com',
            'panel_id' => $panelId,
            'panel_roles' => ['PUBLISH', 'EDIT'],
            'ver' => 4,
            'iat' => time(),
            'exp' => time() + 60,
        ]);

        $claims = $this->validator()->validate($token);

        self::assertSame($userId->toString(), $claims->userId->toString());
        self::assertSame('jan@example.com', $claims->email);
        self::assertSame($panelId, $claims->panelId);
        self::assertSame(['PUBLISH', 'EDIT'], $claims->panelRoles);
        self::assertSame(4, $claims->tokenVersion);
    }

    public function testForeignAudIsAccepted(): void
    {
        // KLUCZOWE (panel-agnostic): token z aud INNEGO panelu MUSI przejść.
        // Dawniej rzucało "Niepoprawne audience" → 401 → pętla przy przełączaniu paneli.
        $token = $this->encode([
            'iss' => self::ISSUER,
            'aud' => Uuid::uuid4()->toString(), // obcy panel
            'user_id' => Uuid::uuid4()->toString(),
            'email' => 'jan@example.com',
            'panel_id' => Uuid::uuid4()->toString(),
            'iat' => time(),
            'exp' => time() + 60,
        ]);

        $claims = $this->validator()->validate($token);
        self::assertSame('jan@example.com', $claims->email);
    }

    public function testMissingAudIsAccepted(): void
    {
        $token = $this->encode([
            'iss' => self::ISSUER,
            'user_id' => Uuid::uuid4()->toString(),
            'email' => 'jan@example.com',
            'iat' => time(),
            'exp' => time() + 60,
        ]);

        $claims = $this->validator()->validate($token);
        self::assertNull($claims->panelId);
    }

    public function testMissingPanelIdIsAccepted(): void
    {
        // panel_id opcjonalny — brak → null, nie wyjątek.
        $token = $this->encode([
            'iss' => self::ISSUER,
            'aud' => Uuid::uuid4()->toString(),
            'user_id' => Uuid::uuid4()->toString(),
            'email' => 'jan@example.com',
            'iat' => time(),
            'exp' => time() + 60,
        ]);

        $claims = $this->validator()->validate($token);
        self::assertNull($claims->panelId);
    }

    public function testIssuerMismatchThrows(): void
    {
        $token = $this->encode([
            'iss' => 'https://evil.example',
            'user_id' => Uuid::uuid4()->toString(),
            'email' => 'jan@example.com',
            'iat' => time(),
            'exp' => time() + 60,
        ]);

        $this->expectException(InvalidJwtException::class);
        $this->validator()->validate($token);
    }

    public function testWrongSignatureThrows(): void
    {
        $token = $this->encode([
            'iss' => self::ISSUER,
            'user_id' => Uuid::uuid4()->toString(),
            'email' => 'jan@example.com',
            'iat' => time(),
            'exp' => time() + 60,
        ]);

        // JWKS serwuje INNY klucz publiczny → podpis nie pasuje.
        $other = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($other);
        $otherDetails = openssl_pkey_get_details($other);
        self::assertNotFalse($otherDetails);

        $this->expectException(InvalidJwtException::class);
        $this->validator($otherDetails['key'])->validate($token);
    }

    public function testExpiredTokenThrows(): void
    {
        $token = $this->encode([
            'iss' => self::ISSUER,
            'user_id' => Uuid::uuid4()->toString(),
            'email' => 'jan@example.com',
            'iat' => time() - 120,
            'exp' => time() - 60,
        ]);

        $this->expectException(InvalidJwtException::class);
        $this->validator()->validate($token);
    }

    public function testMissingEmailThrows(): void
    {
        $token = $this->encode([
            'iss' => self::ISSUER,
            'user_id' => Uuid::uuid4()->toString(),
            'iat' => time(),
            'exp' => time() + 60,
        ]);

        $this->expectException(InvalidJwtException::class);
        $this->validator()->validate($token);
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function encode(array $payload): string
    {
        return JWT::encode($payload, $this->privateKey, 'RS256', self::KID);
    }

    private function validator(?string $jwksPublicKeyPem = null): JwtValidator
    {
        $jwks = JwksTestFactory::withKey($jwksPublicKeyPem ?? $this->publicKeyPem, self::KID, self::ISSUER);

        return new JwtValidator($jwks, self::ISSUER);
    }
}
