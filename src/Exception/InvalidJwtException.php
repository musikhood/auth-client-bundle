<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Exception;

/**
 * Rzucane gdy JWT przekazany do modułu nie nadaje się do zaufania: zły podpis,
 * token wygasł, nie zgadza się issuer lub audience, brak wymaganych claimów.
 *
 * Komunikat opisuje konkretny powód. Logujemy go u siebie, ale nigdy nie
 * wystawiamy klientom.
 */
final class InvalidJwtException extends \RuntimeException
{
}
