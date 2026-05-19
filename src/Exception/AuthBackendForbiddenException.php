<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Exception;

/**
 * Auth server odpowiedział 403 — kredensje są poprawne, ale użytkownik
 * nie ma dostępu do panelu (brak panel_access, konto disabled itp.).
 * Niesie oryginalny tekst z auth servera w `message`, żeby konsument
 * mógł go propagować do frontendu.
 */
final class AuthBackendForbiddenException extends AuthBackendException
{
}
