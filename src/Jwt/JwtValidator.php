<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Jwt;

use Musikhood\AuthClient\Exception\InvalidJwtException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Ramsey\Uuid\Exception\InvalidUuidStringException;
use Ramsey\Uuid\Uuid;

/**
 * Weryfikuje JWT wystawione przez auth server. Sprawdzamy:
 *   1. podpis (kluczami z {@see JwksProvider})
 *   2. `iss` zgodny z AUTH_BASE_URL
 *   3. `exp` jeszcze nie minął (sprawdza firebase/php-jwt)
 *
 * PANEL-AGNOSTYCZNE: świadomie NIE walidujemy `aud`. Te same ciasteczka SSO
 * (BEARER + refresh_token) są ważne na każdym panelu w domenie, więc odrzucanie
 * tokenu po `aud`/`panel_id` było błędne (ping-pong aud → 401 → refresh →
 * wylogowanie przy przełączaniu paneli). Claimy `aud`/`panel_id` zostają w
 * payloadzie jako informacyjne, ale NIE są warunkiem ważności. O dostępie do
 * konkretnego panelu rozstrzyga backendowa introspekcja ({@see \Musikhood\AuthClient\EventListener\AuthValidationListener}) → 403.
 *
 * Zwraca sparsowane claimy jako {@see JwtClaims}. Przy każdym błędzie
 * walidacji rzuca {@see InvalidJwtException} z opisem powodu. Logujemy go
 * u siebie, ale nigdy nie pokazujemy klientowi.
 */
final class JwtValidator
{
    /**
     * Tolerancja różnicy zegarów w sekundach. Stosowana zarówno przy `iat`
     * (dolna granica), jak i `exp` (górna). Dwie sekundy wystarczają na
     * typowe rozjazdy NTP między auth serverem a tą aplikacją.
     */
    private const CLOCK_SKEW_SECONDS = 2;

    public function __construct(
        private readonly JwksProvider $jwksProvider,
        private readonly string $authBaseUrl,
    ) {}

    public function validate(string $token): JwtClaims
    {
        $kid = $this->extractKid($token);
        $key = $this->jwksProvider->getKey($kid);

        // Tolerancja małych różnic zegarów dla firebase/php-jwt.
        // Pole jest statyczne, ale nieszkodliwie: ta sama wartość za każdym razem.
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

        // Świadomie NIE walidujemy `aud` — token jest panel-agnostyczny (patrz
        // docblock klasy). O dostępie do panelu decyduje introspekcja, nie `aud`.

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
    private function buildClaims(array $claims): JwtClaims
    {
        $userIdRaw = $claims['user_id'] ?? null;
        $email = $claims['email'] ?? null;
        $panelIdRaw = $claims['panel_id'] ?? null;
        $iat = $claims['iat'] ?? null;
        $exp = $claims['exp'] ?? null;

        if (!is_string($userIdRaw)) {
            throw new InvalidJwtException('Brak lub niepoprawny claim: user_id');
        }
        if (!is_string($email) || '' === $email) {
            throw new InvalidJwtException('Brak lub niepoprawny claim: email');
        }
        // panel_id jest OPCJONALNY — token panel-agnostyczny (patrz docblock klasy).
        // Wspólne ciasteczko SSO niesie ten sam JWT na wszystkie panele, a część
        // wystawień nie ma panel_id. Twarde wymaganie powodowało 401 → refresh →
        // pętla. O dostępie i rolach decyduje introspekcja.
        $panelId = is_string($panelIdRaw) && '' !== $panelIdRaw ? $panelIdRaw : null;
        if (!is_int($iat) || !is_int($exp)) {
            throw new InvalidJwtException('Brak lub niepoprawny claim: iat/exp');
        }

        try {
            $userId = Uuid::fromString($userIdRaw);
        } catch (InvalidUuidStringException $e) {
            throw new InvalidJwtException('user_id nie jest poprawnym UUID', 0, $e);
        }

        // Auth server od pewnej wersji wystawia claim `display_name`. Starsze
        // tokeny mają `username` z tą samą zawartością — czytamy oba dla
        // kompatybilności wstecznej w okresie migracji.
        $displayName = $this->stringClaim($claims, 'display_name')
            ?? $this->stringClaim($claims, 'username');
        $panelName = $this->stringClaim($claims, 'panel_name');

        $panelRolesRaw = $claims['panel_roles'] ?? [];
        $panelRoles = is_array($panelRolesRaw)
            ? array_values(array_filter($panelRolesRaw, 'is_string'))
            : [];

        // `ver` opcjonalny: stare tokeny (przed Phase 1 auth servera) go nie
        // mają — wtedy null i JwtCookieAuthenticator pomija sprawdzenie wersji
        // (inwalidację dogoni /me poll).
        $tokenVersion = $claims['ver'] ?? null;
        if (null !== $tokenVersion && !is_int($tokenVersion)) {
            throw new InvalidJwtException('Claim ver musi być int');
        }

        return new JwtClaims(
            userId: $userId,
            email: $email,
            displayName: $displayName,
            panelId: $panelId,
            panelName: $panelName,
            panelRoles: $panelRoles,
            issuedAt: (new \DateTimeImmutable())->setTimestamp($iat),
            expiresAt: (new \DateTimeImmutable())->setTimestamp($exp),
            tokenVersion: $tokenVersion,
        );
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function stringClaim(array $claims, string $key): ?string
    {
        return isset($claims[$key]) && is_string($claims[$key]) && '' !== $claims[$key]
            ? $claims[$key]
            : null;
    }
}
