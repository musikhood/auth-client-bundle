<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Http;

use Musikhood\AuthClient\Dto\TokenPair;
use Musikhood\AuthClient\Dto\UserData;
use Musikhood\AuthClient\Exception\AuthBackendException;
use Musikhood\AuthClient\Exception\AuthBackendDeviceMismatchException;
use Musikhood\AuthClient\Exception\AuthBackendForbiddenException;
use Musikhood\AuthClient\Exception\AuthBackendInvalidCredentialsException;
use Musikhood\AuthClient\Exception\AuthBackendMfaAlreadyEnabledException;
use Musikhood\AuthClient\Exception\AuthBackendMfaEnrollmentRequiredException;
use Musikhood\AuthClient\Exception\AuthBackendMfaInvalidCodeException;
use Musikhood\AuthClient\Exception\AuthBackendMfaRequiredException;
use Musikhood\AuthClient\Exception\AuthBackendMfaStepUpException;
use Musikhood\AuthClient\Exception\AuthBackendMfaTokenExpiredException;
use Musikhood\AuthClient\Exception\AuthBackendTooManyAttemptsException;
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
 * 2FA (0.7): pole `code` z body auth servera mapujemy na podklasy wyjątków
 * (AuthBackendMfa*, AuthBackendTooManyAttemptsException, AuthBackendDeviceMismatchException).
 * Odpowiedź bez `code` = zachowanie jak w 0.6. Dane przeglądarki end-usera
 * (IP, UA, X-Device-Fp, `device`) idą przez {@see ClientContextProvider}.
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
        private ?ClientContextProvider $clientContext = null,
    ) {}

    /**
     * @param array<string, mixed>|null $device komponenty fingerprintu z przeglądarki (auth-client >= 2.2)
     *
     * @throws AuthBackendMfaRequiredException           401 mfa_required (mfaToken)
     * @throws AuthBackendMfaEnrollmentRequiredException 403 mfa_enrollment_required (enrollmentUrl)
     * @throws AuthBackendTooManyAttemptsException       429
     * @throws AuthBackendException                      inne 401/403/5xx/transport
     */
    public function login(string $email, string $password, ?array $device = null): TokenPair
    {
        $payload = $this->request(
            'POST',
            '/api/auth/backend/login',
            options: $this->backendOptions(['email' => $email, 'password' => $password], $device),
        );

        return $this->buildTokenPair($payload);
    }

    /**
     * @param array<string, mixed>|null $device
     *
     * @throws AuthBackendDeviceMismatchException 401 device_mismatch (sesja odwołana)
     * @throws AuthBackendException               inne 401/403/5xx/transport
     */
    public function refresh(string $refreshToken, ?array $device = null): TokenPair
    {
        $payload = $this->request(
            'POST',
            '/api/auth/backend/refresh',
            options: $this->backendOptions(['refresh_token' => $refreshToken], $device),
        );

        return $this->buildTokenPair($payload);
    }

    /**
     * Drugi krok logowania 2FA (POST /api/auth/backend/login/mfa).
     *
     * @param array<string, mixed>|null $device
     *
     * @throws AuthBackendMfaInvalidCodeException
     * @throws AuthBackendMfaTokenExpiredException
     * @throws AuthBackendTooManyAttemptsException
     * @throws AuthBackendException
     */
    public function loginMfa(string $mfaToken, ?string $code, ?string $recoveryCode, bool $rememberDevice = false, ?array $device = null): TokenPair
    {
        $payload = $this->request(
            'POST',
            '/api/auth/backend/login/mfa',
            options: $this->backendOptions([
                'mfa_token' => $mfaToken,
                'code' => $code,
                'recovery_code' => $recoveryCode,
                'remember_device' => $rememberDevice,
            ], $device),
        );

        return $this->buildTokenPair($payload);
    }

    /**
     * Step-up sesji (POST /api/auth/backend/session/mfa) — nowa para tokenów z amr otp/recovery.
     *
     * @param array<string, mixed>|null $device
     *
     * @throws AuthBackendException
     */
    public function sessionMfa(string $refreshToken, ?string $code, ?string $recoveryCode, bool $rememberDevice = false, ?array $device = null): TokenPair
    {
        $payload = $this->request(
            'POST',
            '/api/auth/backend/session/mfa',
            options: $this->backendOptions([
                'refresh_token' => $refreshToken,
                'code' => $code,
                'recovery_code' => $recoveryCode,
                'remember_device' => $rememberDevice,
            ], $device),
        );

        return $this->buildTokenPair($payload);
    }

    /**
     * Link do konfiguracji 2FA dla zalogowanego usera (POST /api/auth/backend/mfa/enrollment/request).
     * Wymaga aktualnego hasła usera — sama sesja (refresh token) nie wystarcza.
     *
     * @throws AuthBackendInvalidCredentialsException 401 złe / brak hasła
     * @throws AuthBackendMfaAlreadyEnabledException  409
     * @throws AuthBackendTooManyAttemptsException    429
     * @throws AuthBackendException
     */
    public function requestMfaEnrollment(string $refreshToken, ?string $password): string
    {
        $payload = $this->request(
            'POST',
            '/api/auth/backend/mfa/enrollment/request',
            options: $this->backendOptions(['refresh_token' => $refreshToken, 'password' => $password], null),
        );

        $url = $payload['enrollment_url'] ?? null;
        if (!is_string($url) || '' === $url) {
            throw new AuthBackendException('Niepoprawny payload enrollment (brak enrollment_url)');
        }

        return $url;
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
     * Backendowa introspekcja JWT (ścieżka cookie/SSO) na auth serverze
     * (POST /api/auth/backend/introspect, HTTP Basic + token w body). Panel
     * ustala auth server z poświadczeń klienta (NIE z Origin — wołamy s2s).
     *
     * W ODRÓŻNIENIU od {@see self::getCurrentUser()}: NIE połykamy 403.
     *   - 200            → {@see UserData} (user ma dostęp do panelu klienta),
     *   - 401            → {@see AuthBackendUnauthorizedException} (sesja martwa:
     *                      token nieważny/wygasły, iss/ver, konto disabled),
     *   - 403            → {@see AuthBackendForbiddenException} (sesja żyje, brak
     *                      dostępu do panelu — wołający mapuje na 403 do frontu,
     *                      BEZ czyszczenia cookies / refreshu),
     *   - 5xx/transport  → {@see AuthBackendException} (fail-open u wołającego).
     */
    public function introspectJwt(string $accessToken): UserData
    {
        $payload = $this->request(
            'POST',
            '/api/auth/backend/introspect',
            options: [
                'auth_basic' => [$this->authClientId, $this->authClientSecret],
                'json' => ['token' => $accessToken],
            ],
        );

        return $this->buildUserData($payload);
    }

    /**
     * Introspekcja per-user-per-panel API tokenu na auth serverze
     * (POST /api/auth/backend/api-token/verify, HTTP Basic + nagłówek X-Api-Token).
     * Null = auth server odpowiedział 401 (token nieważny, obcy panel, user
     * disabled lub złe creds). Inne błędy rzucają {@see AuthBackendException} —
     * wywołujący (authenticator) robi fail-closed.
     */
    public function introspectApiToken(string $rawToken): ?UserData
    {
        try {
            $payload = $this->request(
                'POST',
                '/api/auth/backend/api-token/verify',
                options: [
                    'auth_basic' => [$this->authClientId, $this->authClientSecret],
                    'headers' => ['X-Api-Token' => $rawToken],
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
            $body = $this->decodeErrorBody($response);
            $code = is_string($body['code'] ?? null) ? $body['code'] : null;
            $message = is_string($body['error'] ?? null) && '' !== $body['error'] ? $body['error'] : null;

            if ('mfa_required' === $code && is_string($body['mfa_token'] ?? null)) {
                $methods = is_array($body['methods'] ?? null) ? array_values(array_filter($body['methods'], 'is_string')) : [];

                throw new AuthBackendMfaRequiredException($body['mfa_token'], $methods, $message ?? 'Wymagany kod weryfikacji dwuetapowej.');
            }
            match ($code) {
                'invalid_credentials' => throw new AuthBackendInvalidCredentialsException($message ?? 'Nieprawidłowy login lub hasło.'),
                'mfa_invalid_code' => throw new AuthBackendMfaInvalidCodeException($message ?? 'Nieprawidłowy kod weryfikacyjny.'),
                'mfa_code_reused' => throw new AuthBackendMfaInvalidCodeException($message ?? 'Ten kod został już użyty — poczekaj na następny w aplikacji.', AuthBackendMfaInvalidCodeException::CODE_REUSED),
                'mfa_token_expired' => throw new AuthBackendMfaTokenExpiredException($message ?? 'Sesja weryfikacji wygasła. Zaloguj się ponownie.'),
                'device_mismatch' => throw new AuthBackendDeviceMismatchException($message ?? 'Sesja została unieważniona — wykryto zmianę urządzenia.'),
                default => null,
            };

            throw new AuthBackendUnauthorizedException("auth server zwrócił 401 dla {$method} {$path}");
        }

        if (403 === $status) {
            // 403 z auth servera niesie informację, dlaczego user nie wszedł
            // (brak dostępu do panelu, konto disabled). Tekst z `error` w body
            // wystawiamy w exception.message, żeby LoginController mógł go
            // przekazać do frontu.
            $body = $this->decodeErrorBody($response);
            $reason = is_string($body['error'] ?? null) && '' !== $body['error'] ? $body['error'] : 'Brak dostępu.';
            $code = is_string($body['code'] ?? null) ? $body['code'] : null;
            $this->logger->info('AuthBackend: 403 z auth servera', [
                'method' => $method,
                'path' => $path,
                'reason' => $reason,
                'code' => $code,
            ]);
            if ('mfa_enrollment_required' === $code) {
                throw new AuthBackendMfaEnrollmentRequiredException(is_string($body['enrollment_url'] ?? null) ? $body['enrollment_url'] : null, $reason);
            }
            if ('mfa_step_up' === $code) {
                throw new AuthBackendMfaStepUpException($reason);
            }
            throw new AuthBackendForbiddenException($reason);
        }

        if (409 === $status && 'mfa_already_enabled' === ($this->decodeErrorBody($response)['code'] ?? null)) {
            throw new AuthBackendMfaAlreadyEnabledException('Weryfikacja dwuetapowa jest już włączona.');
        }

        if (429 === $status) {
            $retry = $response->getHeaders(false)['retry-after'][0] ?? null;
            $body = $this->decodeErrorBody($response);

            throw new AuthBackendTooManyAttemptsException(
                is_numeric($retry) ? (int) $retry : null,
                is_string($body['error'] ?? null) ? $body['error'] : 'Zbyt wiele prób. Spróbuj ponownie później.',
            );
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

    /**
     * @return array<string, mixed>
     */
    private function decodeErrorBody(\Symfony\Contracts\HttpClient\ResponseInterface $response): array
    {
        try {
            /** @var array<string, mixed> $decoded */
            $decoded = $response->toArray(false);
        } catch (\Throwable) {
            return [];
        }

        return $decoded;
    }

    /**
     * Basic panelu + JSON body (+ `device` gdy przyszedł z przeglądarki) + nagłówki
     * end-usera (X-Client-Ip / X-Client-User-Agent / X-Device-Fp).
     *
     * @param array<string, mixed>      $json
     * @param array<string, mixed>|null $device
     *
     * @return array<string, mixed>
     */
    private function backendOptions(array $json, ?array $device): array
    {
        $device ??= $this->clientContext?->deviceFromBody();
        if (null !== $device) {
            $json['device'] = $device;
        }

        $options = [
            'auth_basic' => [$this->authClientId, $this->authClientSecret],
            'json' => array_filter($json, static fn (mixed $v): bool => null !== $v),
        ];

        $headers = $this->clientContext?->forwardedHeaders() ?? [];
        if ([] !== $headers) {
            $options['headers'] = $headers;
        }

        return $options;
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
