<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Exception;

/** Auth server: 429 `too_many_attempts` (login / MFA rate limit). */
final class AuthBackendTooManyAttemptsException extends AuthBackendException
{
    public function __construct(
        public readonly ?int $retryAfter,
        string $message = 'Zbyt wiele prób. Spróbuj ponownie później.',
    ) {
        parent::__construct($message);
    }
}
