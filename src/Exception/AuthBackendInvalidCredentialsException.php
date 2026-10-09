<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Exception;

/** Auth server: 401 `invalid_credentials` (np. złe hasło przy enrollment/request). */
final class AuthBackendInvalidCredentialsException extends AuthBackendUnauthorizedException
{
}
