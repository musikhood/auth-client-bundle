<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\EventListener;

use Musikhood\AuthClient\Exception\AuthBackendException;
use Musikhood\AuthClient\Http\AuthBackendClient;
use Musikhood\AuthClient\Jwt\JwtClaims;
use Musikhood\AuthClient\Security\JwtCookieAuthenticator;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Sprawdza w auth serverze przy każdym żądaniu, czy użytkownik nadal jest
 * aktywny (nie zablokowany, tokenVersion się zgadza). Wynik cache'ujemy przez
 * `validationCacheTtl` sekund (domyślnie 30s), żeby jeden user spamujący API
 * nie obciążał auth servera.
 *
 * Obsługa błędów:
 *   1. 401 z /me: odrzucamy żądanie (fail closed). Interceptor na froncie
 *      wywoła wtedy /api/token/refresh. Jeśli to też się nie uda, front
 *      czyści ciasteczka i wylogowuje.
 *   2. Timeout albo 5xx: fail open + log. Po N błędach z rzędu otwieramy
 *      circuit breaker na `cb_open_seconds` sekund i nie wołamy /me wcale.
 *      Udane wywołanie resetuje licznik.
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
            $userData = $this->authBackendClient->getCurrentUser($accessToken);
        } catch (AuthBackendException $e) {
            // Błąd transportu lub 5xx. Fail open, doliczamy do licznika breakera.
            $this->recordFailure($e->getMessage());

            return;
        }

        if (null === $userData) {
            // Auth server odpowiedział 401: token unieważniony, user zablokowany
            // albo tokenVersion się nie zgadza. Odrzucamy żądanie. Interceptor
            // frontu wywoła /api/token/refresh, ten też zwróci 401, wyczyści
            // ciasteczka i dokończy wylogowanie.
            throw new UnauthorizedHttpException('Bearer', 'Token no longer valid upstream');
        }

        $this->markValidated($claims);
        $this->resetFailures();
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
