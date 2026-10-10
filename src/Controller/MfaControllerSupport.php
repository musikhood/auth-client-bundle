<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Controller;

use Musikhood\AuthClient\Exception\AuthBackendDeviceMismatchException;
use Musikhood\AuthClient\Exception\AuthBackendException;
use Musikhood\AuthClient\Exception\AuthBackendForbiddenException;
use Musikhood\AuthClient\Exception\AuthBackendInvalidCredentialsException;
use Musikhood\AuthClient\Exception\AuthBackendMfaAlreadyEnabledException;
use Musikhood\AuthClient\Exception\AuthBackendMfaInvalidCodeException;
use Musikhood\AuthClient\Exception\AuthBackendMfaTokenExpiredException;
use Musikhood\AuthClient\Exception\AuthBackendTooManyAttemptsException;
use Musikhood\AuthClient\Exception\AuthBackendUnauthorizedException;
use Musikhood\AuthClient\Http\AuthErrorResponse;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Wspólne mapowanie wyjątków auth servera dla endpointów 2FA bundla.
 *
 * @internal
 */
final class MfaControllerSupport
{
    public static function tooManyAttempts(AuthBackendTooManyAttemptsException $e): JsonResponse
    {
        $response = AuthErrorResponse::create($e->getMessage(), AuthErrorResponse::CODE_TOO_MANY_ATTEMPTS, Response::HTTP_TOO_MANY_REQUESTS);
        if (null !== $e->retryAfter) {
            $response->headers->set('Retry-After', (string) $e->retryAfter);
        }

        return $response;
    }

    /**
     * @return JsonResponse|null null = wyjątek do obsłużenia przez wołającego (np. 5xx)
     */
    public static function map(AuthBackendException $e): ?JsonResponse
    {
        return match (true) {
            $e instanceof AuthBackendTooManyAttemptsException => self::tooManyAttempts($e),
            $e instanceof AuthBackendInvalidCredentialsException => AuthErrorResponse::create($e->getMessage(), AuthErrorResponse::CODE_INVALID_CREDENTIALS, Response::HTTP_UNAUTHORIZED),
            $e instanceof AuthBackendMfaInvalidCodeException => AuthErrorResponse::create($e->getMessage(), $e->errorCode, Response::HTTP_UNAUTHORIZED),
            $e instanceof AuthBackendMfaTokenExpiredException => AuthErrorResponse::create($e->getMessage(), AuthErrorResponse::CODE_MFA_TOKEN_EXPIRED, Response::HTTP_UNAUTHORIZED),
            $e instanceof AuthBackendDeviceMismatchException => AuthErrorResponse::create($e->getMessage(), AuthErrorResponse::CODE_DEVICE_MISMATCH, Response::HTTP_UNAUTHORIZED),
            $e instanceof AuthBackendMfaAlreadyEnabledException => AuthErrorResponse::create($e->getMessage(), AuthErrorResponse::CODE_MFA_ALREADY_ENABLED, Response::HTTP_CONFLICT),
            $e instanceof AuthBackendUnauthorizedException => new JsonResponse(['error' => 'Brak autoryzacji.'], Response::HTTP_UNAUTHORIZED),
            $e instanceof AuthBackendForbiddenException => new JsonResponse(['error' => $e->getMessage()], Response::HTTP_FORBIDDEN),
            default => null,
        };
    }

    /**
     * @param array<string, mixed> $payload
     */
    public static function stringField(array $payload, string $key): ?string
    {
        $value = $payload[$key] ?? null;

        return is_string($value) && '' !== $value ? $value : null;
    }

    /**
     * @return array<string, mixed>
     */
    public static function payload(string $content): array
    {
        $decoded = json_decode($content, true);

        /** @var array<string, mixed> */
        return is_array($decoded) ? $decoded : [];
    }
}
