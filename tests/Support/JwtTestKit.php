<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Support;

use Firebase\JWT\JWT;
use Musikhood\AuthClient\Contract\PanelUserInterface;
use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Musikhood\AuthClient\Cookie\AuthCookieFactory;
use Musikhood\AuthClient\Jwt\JwtValidator;
use Musikhood\AuthClient\Security\UserMirrorSyncer;
use PHPUnit\Framework\TestCase;
use Ramsey\Uuid\Uuid;

/**
 * RSA key + JWKS + validator for tests that need a real, verifiable JWT.
 */
final class JwtTestKit
{
    public const ISSUER = 'https://auth.example';
    public const KID = 'test-kid';

    public readonly JwtValidator $validator;
    private string $privateKey = '';

    public function __construct()
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if (false === $resource) {
            throw new \RuntimeException('openssl');
        }
        openssl_pkey_export($resource, $privateKey);
        $this->privateKey = (string) $privateKey;
        $details = openssl_pkey_get_details($resource);
        if (false === $details) {
            throw new \RuntimeException('openssl');
        }
        $this->validator = new JwtValidator(JwksTestFactory::withKey($details['key'], self::KID, self::ISSUER), self::ISSUER);
    }

    /**
     * @param array<string, mixed> $extra
     */
    public function token(array $extra = []): string
    {
        return JWT::encode([
            'iss' => self::ISSUER,
            'user_id' => Uuid::uuid4()->toString(),
            'email' => 'jan@example.com',
            'iat' => time(),
            'exp' => time() + 60,
        ] + $extra, $this->privateKey, 'RS256', self::KID);
    }

    public static function cookieFactory(): AuthCookieFactory
    {
        return new AuthCookieFactory('BEARER', 'refresh_token', '/', null, true, true, 'none');
    }

    public static function syncer(TestCase $test): UserMirrorSyncer
    {
        $user = (new \ReflectionMethod($test, 'createMock'))->invoke($test, PanelUserInterface::class);
        $user->method('getUserIdentifier')->willReturn('jan@example.com');
        $repo = (new \ReflectionMethod($test, 'createMock'))->invoke($test, PanelUserRepositoryInterface::class);
        $repo->method('findById')->willReturn(null);
        $repo->method('createFromClaims')->willReturn($user);

        return new UserMirrorSyncer($repo);
    }
}
