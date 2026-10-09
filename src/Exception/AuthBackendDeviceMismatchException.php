<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Exception;

/** Auth server: 401 `device_mismatch` przy refreshu — sesja związana z innym urządzeniem została odwołana. */
final class AuthBackendDeviceMismatchException extends AuthBackendUnauthorizedException
{
}
