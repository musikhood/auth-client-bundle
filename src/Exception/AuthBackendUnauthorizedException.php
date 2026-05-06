<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Exception;

/**
 * Auth server jawnie odrzucił dane logowania, refresh token albo access token.
 * Osobny typ od {@see AuthBackendException}, dzięki czemu wywołujący wie, że
 * powinien zakończyć sesję, a nie próbować ponownie po chwili.
 */
final class AuthBackendUnauthorizedException extends AuthBackendException
{
}
