<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Http;

use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Odpowiedzi błędów zgodne z kontraktem auth servera: `{error, code, ...}`.
 * `error` = czytelny komunikat (jak dotąd), `code` = maszynowy kod, po którym
 * rozgałęzia się auth-client >= 2.2. Stare fronty czytają tylko `error`.
 */
final class AuthErrorResponse
{
    public const CODE_INVALID_CREDENTIALS = 'invalid_credentials';
    public const CODE_TOO_MANY_ATTEMPTS = 'too_many_attempts';
    public const CODE_MFA_REQUIRED = 'mfa_required';
    public const CODE_MFA_INVALID_CODE = 'mfa_invalid_code';
    public const CODE_MFA_CODE_REUSED = 'mfa_code_reused';
    public const CODE_MFA_TOKEN_EXPIRED = 'mfa_token_expired';
    public const CODE_MFA_ENROLLMENT_REQUIRED = 'mfa_enrollment_required';
    public const CODE_MFA_ALREADY_ENABLED = 'mfa_already_enabled';
    public const CODE_MFA_STEP_UP = 'mfa_step_up';
    public const CODE_DEVICE_MISMATCH = 'device_mismatch';
    public const CODE_DEVICE_MISMATCH_RECHECK = 'device_mismatch_recheck';

    /**
     * @param array<string, mixed> $extra
     */
    public static function create(string $message, ?string $code, int $status, array $extra = []): JsonResponse
    {
        $body = ['error' => $message];
        if (null !== $code) {
            $body['code'] = $code;
        }
        $response = new JsonResponse($body + $extra, $status);
        $response->setEncodingOptions($response->getEncodingOptions() | JSON_UNESCAPED_SLASHES);

        return $response;
    }
}
