<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Jwt;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Musikhood\AuthClient\Exception\InvalidJwtException;
use Psr\Log\LoggerInterface;
use Ramsey\Uuid\Exception\InvalidUuidStringException;
use Ramsey\Uuid\Uuid;

/**
 * Verify-only walidacja webhook JWT od auth servera (inwalidacja usera, 0s
 * revocation). Osobny od {@see JwtValidator} (user JWT) — webhook niesie inne
 * claimy: `sub` (user_id), `aud` (panel_id konsumenta), `reason`, `panel_id`,
 * `ver`, zamiast `user_id`/`email`/`panel_roles`.
 *
 * Reuse: {@see JwksProvider} (te same klucze RS256 + cache co user JWT). Przy
 * każdym błędzie walidacji rzuca {@see InvalidJwtException} z opisem powodu —
 * logujemy go u siebie, ale nigdy nie pokazujemy nadawcy webhooka.
 */
final class WebhookJwtValidator
{
    private const CLOCK_SKEW_SECONDS = 2;

    /**
     * Znane powody inwalidacji. Forward-compat: nieznany `reason` jest logowany
     * jako warning, ale akceptowany — auth server może dodać nowy powód zanim
     * konsument zaktualizuje paczkę.
     */
    private const KNOWN_REASONS = ['disabled', 'password_changed', 'panel_removed'];

    public function __construct(
        private readonly JwksProvider $jwksProvider,
        private readonly LoggerInterface $logger,
        private readonly string $authBaseUrl,
        private readonly string $authPanelId,
    ) {}

    /**
     * @throws InvalidJwtException
     */
    public function validate(string $token): WebhookClaims
    {
        $kid = $this->extractKid($token);
        $key = $this->jwksProvider->getKey($kid);

        JWT::$leeway = self::CLOCK_SKEW_SECONDS;

        try {
            $decoded = JWT::decode($token, $key);
        } catch (ExpiredException $e) {
            throw new InvalidJwtException('Token wygasł', 0, $e);
        } catch (BeforeValidException $e) {
            throw new InvalidJwtException('Token jeszcze nieważny', 0, $e);
        } catch (SignatureInvalidException $e) {
            throw new InvalidJwtException('Niepoprawny podpis', 0, $e);
        } catch (\Throwable $e) {
            throw new InvalidJwtException('Nie udało się zdekodować tokenu: ' . $e->getMessage(), 0, $e);
        }

        $claims = (array) $decoded;

        $expectedIss = rtrim($this->authBaseUrl, '/');
        $actualIss = isset($claims['iss']) ? rtrim((string) $claims['iss'], '/') : null;
        if ($actualIss !== $expectedIss) {
            throw new InvalidJwtException("Niepoprawny issuer: oczekiwano '{$expectedIss}', otrzymano '{$actualIss}'");
        }

        // `aud` dokładne dopasowanie (===), nie prefix — webhook do tego panelu
        // ma aud=<nasz panel_id>; webhook adresowany do innego panelu / mirror
        // (aud='mirror') musi być odrzucony.
        if (($claims['aud'] ?? null) !== $this->authPanelId) {
            $aud = is_scalar($claims['aud'] ?? null) ? (string) $claims['aud'] : '<missing>';
            throw new InvalidJwtException("Niepoprawne audience: oczekiwano '{$this->authPanelId}', otrzymano '{$aud}'");
        }

        return $this->buildClaims($claims);
    }

    private function extractKid(string $token): ?string
    {
        $parts = explode('.', $token);
        if (3 !== count($parts)) {
            throw new InvalidJwtException('Token nie wygląda na poprawny JWT (powinny być 3 części)');
        }

        $headerJson = JWT::urlsafeB64Decode($parts[0]);
        $header = json_decode($headerJson, true);
        if (!is_array($header)) {
            throw new InvalidJwtException('Nagłówek tokenu nie jest poprawnym JSON-em');
        }

        $kid = $header['kid'] ?? null;

        return is_string($kid) ? $kid : null;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function buildClaims(array $claims): WebhookClaims
    {
        $subRaw = $claims['sub'] ?? null;
        $reason = $claims['reason'] ?? null;
        $ver = $claims['ver'] ?? null;
        $iat = $claims['iat'] ?? null;
        $exp = $claims['exp'] ?? null;

        if (!is_string($subRaw) || '' === $subRaw) {
            throw new InvalidJwtException('Brak lub niepoprawny claim: sub');
        }
        if (!is_string($reason) || '' === $reason) {
            throw new InvalidJwtException('Brak lub niepoprawny claim: reason');
        }
        // `ver` obowiązkowy — auth server od Phase 1+2 zawsze go ustawia.
        if (!is_int($ver)) {
            throw new InvalidJwtException('Brak lub niepoprawny claim: ver');
        }
        if (!is_int($iat) || !is_int($exp)) {
            throw new InvalidJwtException('Brak lub niepoprawny claim: iat/exp');
        }

        try {
            $userId = Uuid::fromString($subRaw);
        } catch (InvalidUuidStringException $e) {
            throw new InvalidJwtException('sub nie jest poprawnym UUID', 0, $e);
        }

        if (!in_array($reason, self::KNOWN_REASONS, true)) {
            // Forward-compat: akceptujemy nieznany powód, ale logujemy żeby
            // wychwycić rozjazd kontraktu auth server ↔ paczka.
            $this->logger->warning('webhook: nieznany reason', ['reason' => $reason]);
        }

        $panelIdRaw = $claims['panel_id'] ?? null;
        $panelId = is_string($panelIdRaw) && '' !== $panelIdRaw ? $panelIdRaw : null;

        return new WebhookClaims(
            userId: $userId,
            reason: $reason,
            panelId: $panelId,
            tokenVersion: $ver,
            issuedAt: (new \DateTimeImmutable())->setTimestamp($iat),
            expiresAt: (new \DateTimeImmutable())->setTimestamp($exp),
        );
    }
}
