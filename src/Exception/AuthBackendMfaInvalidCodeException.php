<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Exception;

/**
 * Auth server: 401 `mfa_invalid_code` albo `mfa_code_reused` (poprawny kod,
 * ale jego krok czasowy był już użyty). `errorCode` = kod z auth servera,
 * przekazywany frontowi 1:1 (auth-client: `MfaInvalidCodeError.reason`).
 */
final class AuthBackendMfaInvalidCodeException extends AuthBackendUnauthorizedException
{
    public const CODE_INVALID = 'mfa_invalid_code';
    public const CODE_REUSED = 'mfa_code_reused';

    public function __construct(
        string $message = '',
        public readonly string $errorCode = self::CODE_INVALID,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public function isReused(): bool
    {
        return self::CODE_REUSED === $this->errorCode;
    }
}
