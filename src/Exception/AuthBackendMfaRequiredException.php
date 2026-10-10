<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Exception;

/**
 * Auth server: 401 `mfa_required` — hasło OK, potrzebny drugi składnik.
 * Podklasa Unauthorized: kod, który nie zna 2FA, potraktuje to jak złe dane
 * logowania (fail-closed — nigdy nie zaloguje bez kodu).
 */
final class AuthBackendMfaRequiredException extends AuthBackendUnauthorizedException
{
    /**
     * @param list<string> $methods
     */
    public function __construct(
        public readonly string $mfaToken,
        public readonly array $methods,
        string $message = 'Wymagany kod weryfikacji dwuetapowej.',
    ) {
        parent::__construct($message);
    }
}
