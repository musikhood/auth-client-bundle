<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Exception;

/** Auth server: 401 `mfa_token_expired` — mfa_token wygasł / zużyty / limit prób. */
final class AuthBackendMfaTokenExpiredException extends AuthBackendUnauthorizedException
{
}
