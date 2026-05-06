<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Exception;

/**
 * Rzucane gdy zapytanie do auth servera nie powiedzie się z innego powodu niż
 * błędne dane logowania: timeout, błąd sieci, odpowiedź 5xx, niepoprawny
 * payload.
 *
 * Wywołujący decyduje co z tym zrobić: ufać dotychczasowej sesji
 * (fail open, np. introspekcja) czy odrzucić żądanie (fail closed, np. login).
 *
 * Dla 401 (odrzucone dane logowania lub refresh token) używamy osobnego
 * {@see AuthBackendUnauthorizedException}.
 */
class AuthBackendException extends \RuntimeException
{
}
