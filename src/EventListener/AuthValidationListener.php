<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\EventListener;

use Musikhood\AuthClient\Exception\AuthBackendException;
use Musikhood\AuthClient\Exception\AuthBackendForbiddenException;
use Musikhood\AuthClient\Exception\AuthBackendUnauthorizedException;
use Musikhood\AuthClient\Http\AuthBackendClient;
use Musikhood\AuthClient\Jwt\JwtClaims;
use Musikhood\AuthClient\Security\JwtCookieAuthenticator;
use Musikhood\AuthClient\Security\UserMirrorSyncer;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Ramsey\Uuid\UuidInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Sprawdza w auth serverze przy każdym żądaniu, czy użytkownik ma dostęp do
 * TEGO panelu i czy sesja jest wciąż ważna. Robi to przez backendową
 * introspekcję (POST /api/auth/backend/introspect) — panel ustala auth server
 * z poświadczeń klienta (NIE z Origin: wołamy server-to-server bez Origin, więc
 * bramka po /me + Origin nigdy by nie zwróciła 403). Wynik cache'ujemy przez
 * `validationCacheTtl` sekund (domyślnie 30s).
 *
 * Obsługa odpowiedzi:
 *   1. 200: user ma dostęp → sync lokalnej kopii + cache OK.
 *   2. 401 (sesja martwa: token nieważny/wygasły, iss/ver, konto disabled):
 *      odrzucamy 401. Interceptor frontu wywoła /api/token/refresh; jeśli i to
 *      się nie uda, ciasteczka są czyszczone i sesja kończona.
 *   3. 403 (brak dostępu do panelu, sesja ŻYJE): odrzucamy 403 przez
 *      AccessDeniedHttpException. Front (paczka JS) klasyfikuje to jako
 *      PanelAccessDeniedError — BEZ refreshu, BEZ czyszczenia ciasteczek, BEZ
 *      broadcastu. Sesja na innych panelach zostaje nienaruszona.
 *   4. Timeout/5xx/transport: fail OPEN + log (NIE wylogowujemy przy awarii
 *      mastera). Po N błędach z rzędu otwieramy circuit breaker na
 *      `cb_open_seconds` i nie wołamy introspekcji wcale. Udane wywołanie resetuje.
 *
 * Klucze cache i breakera żyją w `cache.app` (PSR-6). Ewentualne wyrzucenie
 * z cache jest nieszkodliwe, oba klucze są krótkotrwałe.
 */
#[AsEventListener(event: KernelEvents::CONTROLLER, priority: 0)]
final readonly class AuthValidationListener
{
    private const CACHE_KEY_VALIDATED = 'auth_client_validated_';
    private const CACHE_KEY_FAILURES = 'auth_client_cb_failures';
    private const CACHE_KEY_OPEN_UNTIL = 'auth_client_cb_open_until';

    public function __construct(
        private AuthBackendClient $authBackendClient,
        private UserMirrorSyncer $userMirrorSyncer,
        #[Autowire(service: 'cache.app')]
        private CacheItemPoolInterface $cache,
        private LoggerInterface $logger,
        private int $validationCacheTtl,
        private int $circuitBreakerFailureThreshold,
        private int $circuitBreakerOpenSeconds,
    ) {}

    public function __invoke(ControllerEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $accessToken = $request->attributes->get(JwtCookieAuthenticator::ATTR_ACCESS_TOKEN);
        $claims = $request->attributes->get(JwtCookieAuthenticator::ATTR_CLAIMS);

        if (!is_string($accessToken) || !$claims instanceof JwtClaims) {
            return;
        }

        if ($this->isCacheFresh($claims)) {
            return;
        }

        if ($this->isCircuitOpen()) {
            $this->logger->info('AuthValidation: circuit breaker otwarty, pomijam introspekcję');

            return;
        }

        try {
            $userData = $this->authBackendClient->introspectJwt($accessToken);
        } catch (AuthBackendForbiddenException $e) {
            // 403: sesja ŻYJE, ale user nie ma dostępu do tego panelu. Rzucamy
            // AccessDeniedHttpException (HttpException — NIE security'owy
            // AccessDeniedException, którego łapie firewall ExceptionListener i
            // robi 401/redirect). Bąbelkuje do kernela → 403 → ExceptionListener
            // konsumenta. Front: PanelAccessDeniedError (bez refreshu/czyszczenia).
            // NIE doliczamy do breakera — to nie awaria mastera.
            throw new AccessDeniedHttpException($e->getMessage(), $e);
        } catch (AuthBackendUnauthorizedException) {
            // 401: sesja martwa (token nieważny/wygasły, iss/ver, konto disabled).
            // Interceptor frontu wywoła /api/token/refresh; jeśli i to padnie,
            // ciasteczka są czyszczone i sesja kończona.
            throw new UnauthorizedHttpException('Bearer', 'Token nie jest już ważny na serwerze uwierzytelniania.');
        } catch (AuthBackendException $e) {
            // Błąd transportu lub 5xx. Fail OPEN, doliczamy do licznika breakera —
            // NIE wylogowujemy przy awarii mastera.
            $this->recordFailure($e->getMessage());

            return;
        }

        // Auth server zwrócił 200 — to nasze źródło prawdy. Synchronizujemy
        // lokalną kopię (email, displayName, role per-panel, flaga disabled).
        // Dzięki temu zmiany w panelu admin auth servera (zmiana ról,
        // displayName, blokada/odblokowanie konta) propagują się do
        // mikroserwisu w czasie cache TTL (~30s) bez konieczności
        // podbijania tokenVersion.
        //
        // disabled NIE jest tu sprawdzane osobno — auth server zwraca 401 dla
        // disabled (introspekcja waliduje sesję), więc 200 = konto aktywne.
        $this->userMirrorSyncer->syncFromMe($userData);

        $this->markValidated($claims);
        $this->resetFailures();
    }

    /**
     * Wymusza ponowną walidację usera przy najbliższym requeście (kasuje wpis
     * `auth_client_validated_<userId>`). Wołane przez webhook 0s revocation —
     * listener jest właścicielem tego klucza cache, więc inwalidacja idzie przez
     * niego, a nie przez ręczne składanie klucza po stronie controllera.
     */
    public function invalidateValidatedCache(UuidInterface $userId): void
    {
        $this->cache->deleteItem(self::CACHE_KEY_VALIDATED . $userId->toString());
    }

    private function isCacheFresh(JwtClaims $claims): bool
    {
        $item = $this->cache->getItem(self::CACHE_KEY_VALIDATED . $claims->userId->toString());

        return $item->isHit();
    }

    private function markValidated(JwtClaims $claims): void
    {
        $item = $this->cache->getItem(self::CACHE_KEY_VALIDATED . $claims->userId->toString());
        $item->set(time());
        $item->expiresAfter($this->validationCacheTtl);
        $this->cache->save($item);
    }

    private function isCircuitOpen(): bool
    {
        $item = $this->cache->getItem(self::CACHE_KEY_OPEN_UNTIL);

        return $item->isHit();
    }

    private function recordFailure(string $reason): void
    {
        $failuresItem = $this->cache->getItem(self::CACHE_KEY_FAILURES);
        $count = $failuresItem->isHit() ? (int) $failuresItem->get() : 0;
        ++$count;
        $failuresItem->set($count);
        $failuresItem->expiresAfter($this->circuitBreakerOpenSeconds * 5);
        $this->cache->save($failuresItem);

        $this->logger->warning('AuthValidation: błąd po stronie auth servera', [
            'consecutive_failures' => $count,
            'reason' => $reason,
        ]);

        if ($count >= $this->circuitBreakerFailureThreshold) {
            $openItem = $this->cache->getItem(self::CACHE_KEY_OPEN_UNTIL);
            $openItem->set(time() + $this->circuitBreakerOpenSeconds);
            $openItem->expiresAfter($this->circuitBreakerOpenSeconds);
            $this->cache->save($openItem);

            $this->logger->error('AuthValidation: otwarty circuit breaker', [
                'open_seconds' => $this->circuitBreakerOpenSeconds,
                'consecutive_failures' => $count,
            ]);
        }
    }

    private function resetFailures(): void
    {
        $this->cache->deleteItem(self::CACHE_KEY_FAILURES);
        $this->cache->deleteItem(self::CACHE_KEY_OPEN_UNTIL);
    }
}
