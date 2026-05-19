<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Http;

use Musikhood\AuthClient\Dto\TokenPair;
use Musikhood\AuthClient\Dto\UserData;
use Musikhood\AuthClient\Exception\AuthBackendException;
use Musikhood\AuthClient\Exception\AuthBackendForbiddenException;
use Musikhood\AuthClient\Exception\AuthBackendUnauthorizedException;
use Psr\Log\LoggerInterface;
use Ramsey\Uuid\Uuid;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Wrapper HTTP nad backend-client API auth servera.
 *
 * Endpointy server-to-server (`/api/auth/backend/*`) wymagają HTTP Basic auth
 * z parą `(client_id, client_secret)` wygenerowaną w panelu admin auth servera.
 *
 * Endpoint `/api/v1/user/me` wymaga access tokena JWT w nagłówku
 * `Authorization: Bearer <token>`.
 *
 * Przy 401 rzucamy {@see AuthBackendUnauthorizedException}. Inne błędy
 * (timeout, błąd transportu, 5xx, niepoprawny JSON) rzucają ogólny
 * {@see AuthBackendException}. Wywołujący decyduje co dalej: fail open
 * czy fail closed.
 */
final readonly class AuthBackendClient
{
    public function __construct(
        private HttpClientInterface $httpClient,
        private LoggerInterface $logger,
        private string $authBaseUrl,
        private string $authClientId,
        private string $authClientSecret,
        private float $authHttpTimeout,
        private float $authHttpMaxDuration,
    ) {}

    public function login(string $email, string $password): TokenPair
    {
        $payload = $this->request(
            'POST',
            '/api/auth/backend/login',
            options: [
                'auth_basic' => [$this->authClientId, $this->authClientSecret],
                'json' => ['email' => $email, 'password' => $password],
            ],
        );

        return $this->buildTokenPair($payload);
    }

    public function refresh(string $refreshToken): TokenPair
    {
        $payload = $this->request(
            'POST',
            '/api/auth/backend/refresh',
            options: [
                'auth_basic' => [$this->authClientId, $this->authClientSecret],
                'json' => ['refresh_token' => $refreshToken],
            ],
        );

        return $this->buildTokenPair($payload);
    }

    public function logout(string $refreshToken): void
    {
        // Auth server traktuje to idempotentnie: 200 lub 204 znaczy "już nie ma".
        // 401 ignorujemy: jeśli refresh_token był już unieważniony, i tak
        // chcemy doczyścić lokalną sesję.
        try {
            $this->request(
                'POST',
                '/api/auth/backend/logout',
                options: [
                    'auth_basic' => [$this->authClientId, $this->authClientSecret],
                    'json' => ['refresh_token' => $refreshToken],
                ],
            );
        } catch (AuthBackendUnauthorizedException) {
            // refresh_token już unieważniony lub nieznany, w porządku, nie ma czego unieważniać.
        }
    }

    /**
     * Zwraca dane użytkownika dla podanego bearer tokena. Null oznacza że
     * auth server odpowiedział 401 (token wygasł, user zablokowany lub
     * tokenVersion się nie zgadza). Inne błędy rzucają
     * {@see AuthBackendException}. Wywołujący decyduje co dalej.
     */
    public function getCurrentUser(string $accessToken): ?UserData
    {
        try {
            $payload = $this->request(
                'GET',
                '/api/v1/user/me',
                options: [
                    'headers' => ['Authorization' => 'Bearer ' . $accessToken],
                ],
            );
        } catch (AuthBackendUnauthorizedException) {
            return null;
        }

        return $this->buildUserData($payload);
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    private function request(string $method, string $path, array $options): array
    {
        $url = rtrim($this->authBaseUrl, '/') . $path;
        $options += [
            'timeout' => $this->authHttpTimeout,
            'max_duration' => $this->authHttpMaxDuration,
        ];

        try {
            $response = $this->httpClient->request($method, $url, $options);
            $status = $response->getStatusCode();
        } catch (TransportExceptionInterface $e) {
            $this->logger->warning('AuthBackend: błąd transportu', [
                'method' => $method,
                'path' => $path,
                'error' => $e->getMessage(),
            ]);
            throw new AuthBackendException("Błąd transportu przy {$method} {$path}: {$e->getMessage()}", 0, $e);
        }

        if (401 === $status) {
            throw new AuthBackendUnauthorizedException("auth server zwrócił 401 dla {$method} {$path}");
        }

        if (403 === $status) {
            // 403 z auth servera niesie informację, dlaczego user nie wszedł
            // (brak dostępu do panelu, konto disabled). Tekst z `error` w body
            // wystawiamy w exception.message, żeby LoginController mógł go
            // przekazać do frontu.
            $reason = $this->extractErrorMessage($response) ?? 'Brak dostępu.';
            $this->logger->info('AuthBackend: 403 z auth servera', [
                'method' => $method,
                'path' => $path,
                'reason' => $reason,
            ]);
            throw new AuthBackendForbiddenException($reason);
        }

        if ($status >= 400) {
            $body = $this->safeBody($response);
            $this->logger->warning('AuthBackend: odpowiedź spoza 2xx', [
                'method' => $method,
                'path' => $path,
                'status' => $status,
                'body' => $body,
            ]);
            throw new AuthBackendException("auth server zwrócił {$status} dla {$method} {$path}");
        }

        try {
            /** @var array<string, mixed> $decoded */
            $decoded = $response->toArray(false);
        } catch (ExceptionInterface $e) {
            throw new AuthBackendException("Niepoprawny JSON z {$method} {$path}: {$e->getMessage()}", 0, $e);
        }

        return $decoded;
    }

    private function extractErrorMessage(\Symfony\Contracts\HttpClient\ResponseInterface $response): ?string
    {
        try {
            /** @var array<string, mixed> $decoded */
            $decoded = $response->toArray(false);
        } catch (\Throwable) {
            return null;
        }

        $error = $decoded['error'] ?? null;

        return is_string($error) && '' !== $error ? $error : null;
    }

    private function safeBody(\Symfony\Contracts\HttpClient\ResponseInterface $response): string
    {
        try {
            return substr($response->getContent(false), 0, 512);
        } catch (\Throwable) {
            return '<body unreadable>';
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function buildTokenPair(array $payload): TokenPair
    {
        $token = $payload['token'] ?? null;
        $refresh = $payload['refresh_token'] ?? null;
        $expiration = $payload['refresh_token_expiration'] ?? null;

        if (!is_string($token) || '' === $token
            || !is_string($refresh) || '' === $refresh
            || !is_int($expiration)) {
            throw new AuthBackendException(
                'Niepoprawny payload pary tokenów (brak token, refresh_token lub refresh_token_expiration)'
            );
        }

        return new TokenPair(
            accessToken: $token,
            refreshToken: $refresh,
            refreshTokenExpiresAt: (new \DateTimeImmutable())->setTimestamp($expiration),
        );
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function buildUserData(array $payload): UserData
    {
        $id = $payload['id'] ?? null;
        $email = $payload['email'] ?? null;
        $roles = $payload['roles'] ?? null;

        if (!is_string($id) || '' === $id
            || !is_string($email) || '' === $email
            || !is_array($roles)) {
            throw new AuthBackendException('Niepoprawny payload /me (brak id, email lub roles)');
        }

        $displayName = isset($payload['displayName']) && is_string($payload['displayName']) && '' !== $payload['displayName']
            ? $payload['displayName']
            : null;

        $panelId = null;
        if (isset($payload['panelId']) && is_string($payload['panelId']) && '' !== $payload['panelId']) {
            try {
                $panelId = Uuid::fromString($payload['panelId']);
            } catch (\Throwable) {
                // niepoprawny UUID — traktujemy tak samo jak brak panelu
                $panelId = null;
            }
        }

        $panelName = isset($payload['panelName']) && is_string($payload['panelName']) && '' !== $payload['panelName']
            ? $payload['panelName']
            : null;

        $panelRolesRaw = $payload['panelRoles'] ?? [];
        $panelRoles = is_array($panelRolesRaw)
            ? array_values(array_filter($panelRolesRaw, 'is_string'))
            : [];

        $disabled = isset($payload['disabled']) ? (bool) $payload['disabled'] : false;

        return new UserData(
            id: Uuid::fromString($id),
            email: $email,
            displayName: $displayName,
            roles: array_values(array_filter($roles, 'is_string')),
            panelId: $panelId,
            panelName: $panelName,
            panelRoles: $panelRoles,
            disabled: $disabled,
        );
    }
}
