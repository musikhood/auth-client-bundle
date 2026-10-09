<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Exception;

/**
 * Auth server: 403 `mfa_step_up` (introspekcja) — sesja żyje, ale panel wymaga
 * potwierdzenia kodem 2FA. Front (auth-client >= 2.2) pokazuje modal step-up.
 */
final class AuthBackendMfaStepUpException extends AuthBackendForbiddenException
{
}
