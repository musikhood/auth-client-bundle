<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Jwt;

use Musikhood\AuthClient\Exception\AuthBackendException;
use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Pobiera i cache'uje dokument JWKS z auth servera. Zwraca klucze RS256 do
 * weryfikacji podpisu JWT, indeksowane po `kid`. Gotowe do przekazania do
 * Firebase\JWT\JWT::decode().
 *
 * JWKS cache'ujemy przez `auth_client.jwks_cache_ttl` sekund (domyślnie 1h,
 * tyle samo co HTTP cache na auth serverze).
 *
 * Jeśli nie znajdziemy klucza dla danego `kid`, wymuszamy jednorazowo
 * świeże pobranie. Dzięki temu rotacja kluczy na auth serverze nie wymaga
 * ręcznego czyszczenia cache.
 */
final class JwksProvider
{
    private const CACHE_KEY = 'auth_client_jwks';

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly CacheInterface $cache,
        private readonly LoggerInterface $logger,
        private readonly string $authBaseUrl,
        private readonly int $jwksCacheTtl,
        private readonly float $authHttpTimeout,
        private readonly float $authHttpMaxDuration,
    ) {}

    /**
     * @return Key klucz do weryfikacji podpisu dla danego kid. Jeśli $kid
     *             jest null i JWKS ma dokładnie jeden wpis, zwracamy ten
     *             jedyny klucz.
     */
    public function getKey(?string $kid): Key
    {
        $keys = $this->parseKeys($this->loadRawJwks(forceRefresh: false));

        $key = $this->pickKey($keys, $kid);
        if (null !== $key) {
            return $key;
        }

        // Nieznany kid. Wymuszamy świeże pobranie, na wypadek rotacji kluczy.
        $this->logger->info('JWKS: kid nie znaleziony w cache, wymuszam refresh', ['kid' => $kid]);
        $keys = $this->parseKeys($this->loadRawJwks(forceRefresh: true));

        $key = $this->pickKey($keys, $kid);
        if (null !== $key) {
            return $key;
        }

        throw new AuthBackendException("JWKS nie zawiera klucza dla kid '{$kid}'");
    }

    /**
     * @param array<string, Key> $keys
     */
    private function pickKey(array $keys, ?string $kid): ?Key
    {
        if (null !== $kid) {
            return $keys[$kid] ?? null;
        }

        return 1 === count($keys) ? array_values($keys)[0] : null;
    }

    /**
     * Parsuje surowy dokument JWKS na obiekty Firebase\JWT\Key. Robimy to
     * przy każdym wywołaniu (a nie cache'ujemy wyniku), bo Key opakowuje
     * zasób OpenSSLAsymmetricKey, którego nie da się serializować do cache.
     *
     * @param array<string, mixed> $rawJwks
     * @return array<string, Key>
     */
    private function parseKeys(array $rawJwks): array
    {
        try {
            return JWK::parseKeySet($rawJwks, 'RS256');
        } catch (\Throwable $e) {
            throw new AuthBackendException('Nie udało się sparsować JWKS: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * @return array<string, mixed> surowy dokument JWKS w formacie `{"keys": [...]}`
     */
    private function loadRawJwks(bool $forceRefresh): array
    {
        if ($forceRefresh) {
            $this->cache->delete(self::CACHE_KEY);
        }

        return $this->cache->get(self::CACHE_KEY, function (ItemInterface $item): array {
            $item->expiresAfter($this->jwksCacheTtl);

            return $this->fetchJwks();
        });
    }

    /**
     * @return array<string, mixed>
     */
    private function fetchJwks(): array
    {
        $url = rtrim($this->authBaseUrl, '/') . '/.well-known/jwks.json';

        try {
            $response = $this->httpClient->request('GET', $url, [
                'timeout' => $this->authHttpTimeout,
                'max_duration' => $this->authHttpMaxDuration,
            ]);

            if (200 !== $response->getStatusCode()) {
                throw new AuthBackendException("Endpoint JWKS zwrócił {$response->getStatusCode()}");
            }

            /** @var array<string, mixed> $payload */
            $payload = $response->toArray(false);
        } catch (ExceptionInterface $e) {
            throw new AuthBackendException('Nie udało się pobrać JWKS: ' . $e->getMessage(), 0, $e);
        }

        if (!isset($payload['keys']) || !is_array($payload['keys']) || [] === $payload['keys']) {
            throw new AuthBackendException('Odpowiedź JWKS nie zawiera kluczy');
        }

        return $payload;
    }
}
