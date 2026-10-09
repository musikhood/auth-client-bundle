<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Security;

use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

/**
 * X-Device-Fp ≠ claim `fph` w trybie `device_binding.mode: enforce`.
 * JwtCookieAuthenticator mapuje to na 401 `device_mismatch_recheck`.
 */
final class DeviceMismatchAuthenticationException extends CustomUserMessageAuthenticationException
{
}
