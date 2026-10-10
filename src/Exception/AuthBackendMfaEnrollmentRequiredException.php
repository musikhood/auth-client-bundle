<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Exception;

/**
 * Auth server: 403 `mfa_enrollment_required` — panel wymaga 2FA, user go nie ma.
 */
final class AuthBackendMfaEnrollmentRequiredException extends AuthBackendForbiddenException
{
    public function __construct(
        public readonly ?string $enrollmentUrl,
        string $message = 'Ten panel wymaga weryfikacji dwuetapowej. Skonfiguruj ją, aby kontynuować.',
    ) {
        parent::__construct($message);
    }
}
