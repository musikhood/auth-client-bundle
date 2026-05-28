<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Support;

use Musikhood\AuthClient\Jwt\JwksProvider;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Buduje prawdziwy JwksProvider (klasa final — nie mockowalna) zasilony JWKS-em
 * zbudowanym z testowego klucza publicznego RSA. Dzięki temu test przechodzi
 * przez realne JWK::parseKeySet zamiast mockować provider.
 */
final class JwksTestFactory
{
    /**
     * @param string $publicKeyPem PEM klucza publicznego RSA
     */
    public static function withKey(string $publicKeyPem, string $kid, string $authBaseUrl): JwksProvider
    {
        $jwksDocument = json_encode(['keys' => [self::rsaPublicKeyToJwk($publicKeyPem, $kid)]], JSON_THROW_ON_ERROR);

        $httpClient = new MockHttpClient(new MockResponse($jwksDocument, [
            'http_code' => 200,
            'response_headers' => ['content-type' => 'application/json'],
        ]));

        return new JwksProvider(
            $httpClient,
            new ArrayAdapter(),
            new NullLogger(),
            $authBaseUrl,
            3600,
            5.0,
            10.0,
        );
    }

    /**
     * @return array{kty: string, use: string, alg: string, kid: string, n: string, e: string}
     */
    private static function rsaPublicKeyToJwk(string $publicKeyPem, string $kid): array
    {
        $resource = openssl_pkey_get_public($publicKeyPem);
        if (false === $resource) {
            throw new \RuntimeException('Nie udało się sparsować klucza publicznego w teście.');
        }

        $details = openssl_pkey_get_details($resource);
        if (false === $details || !isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new \RuntimeException('Klucz testowy nie jest RSA.');
        }

        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $kid,
            'n' => self::base64UrlEncode($details['rsa']['n']),
            'e' => self::base64UrlEncode($details['rsa']['e']),
        ];
    }

    private static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
