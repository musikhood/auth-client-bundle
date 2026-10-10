<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Exception;

/** Auth server: 409 `mfa_already_enabled`. */
final class AuthBackendMfaAlreadyEnabledException extends AuthBackendException
{
}
