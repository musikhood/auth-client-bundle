<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Doctor;

use Composer\InstalledVersions;
use Musikhood\AuthClient\Cookie\AuthCookieFactory;
use Musikhood\AuthClient\DependencyInjection\Configuration;
use Musikhood\AuthClient\Doctor\SecurityCoverage\SecurityCoverageInspectorInterface;
use Musikhood\AuthClient\Routing\PublicRoutes;
use Musikhood\AuthClient\Security\JwtCookieAuthenticator;
use Psr\Log\LoggerInterface;
use Ramsey\Uuid\Uuid;
use Symfony\Component\DependencyInjection\Exception\EnvNotFoundException;
use Symfony\Component\DependencyInjection\Exception\ParameterNotFoundException;
use Symfony\Component\DependencyInjection\ParameterBag\ContainerBagInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientException;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Diagnoses a panel's integration with the auth server (`auth-client:doctor`).
 *
 * Every check returns a {@see CheckResult}; none of them prints secret values.
 * Remote checks are side-effect free:
 *   - JWKS: GET /.well-known/jwks.json;
 *   - client credentials: POST /api/auth/backend/introspect WITHOUT a token —
 *     the auth server answers 401 + `WWW-Authenticate: Basic` for bad Basic
 *     credentials and a plain 401 ("no token") for valid ones;
 *   - 2FA support: POST /api/auth/backend/login/mfa without credentials —
 *     401 = route exists, 404 = auth server older than the bundle requires;
 *   - panel id (optional, needs `--access-token`): introspection of a real
 *     session returns the panel of the calling client.
 */
final readonly class AuthDoctor
{
    private const PUBLIC_ACCESS = 'PUBLIC_ACCESS';

    /** @var array<string, string> config parameter => env variable it usually comes from */
    private const REQUIRED_PARAMETERS = [
        'auth_client.base_url' => 'AUTH_BASE_URL',
        'auth_client.panel_id' => 'AUTH_PANEL_ID',
        'auth_client.client_id' => 'AUTH_CLIENT_ID',
        'auth_client.client_secret' => 'AUTH_CLIENT_SECRET',
    ];

    public function __construct(
        private ContainerBagInterface $parameters,
        private HttpClientInterface $httpClient,
        private SecurityCoverageInspectorInterface $securityInspector,
        private AuthCookieFactory $cookieFactory,
        private LoggerInterface $logger,
    ) {}

    /**
     * @return list<CheckResult>
     */
    public function run(?string $accessToken = null): array
    {
        $results = [$this->bundleVersion()];

        [$config, $configResults] = $this->readConfig();
        array_push($results, ...$configResults);

        if (null !== $config) {
            array_push($results, ...$this->remoteChecks($config, $accessToken));
        } else {
            $results[] = CheckResult::skipped('Połączenie z auth serverem', 'pominięte — najpierw uzupełnij konfigurację');
        }

        array_push($results, ...$this->securityChecks());
        $results[] = $this->corsCheck();
        $results[] = $this->cookieCheck();
        $results[] = $this->trustedProxiesCheck();

        return $results;
    }

    /**
     * @param list<CheckResult> $results
     */
    public static function hasFailures(array $results): bool
    {
        foreach ($results as $result) {
            if (CheckStatus::Failure === $result->status) {
                return true;
            }
        }

        return false;
    }

    private function bundleVersion(): CheckResult
    {
        $version = class_exists(InstalledVersions::class) && InstalledVersions::isInstalled('musikhood/auth-client-bundle')
            ? (InstalledVersions::getPrettyVersion('musikhood/auth-client-bundle') ?? 'nieznana')
            : 'nieznana';

        return CheckResult::ok('Wersja auth-client-bundle', $version);
    }

    /**
     * @return array{0: array{base_url: string, panel_id: string, client_id: string, client_secret: string}|null, 1: list<CheckResult>}
     */
    private function readConfig(): array
    {
        $values = [];
        $results = [];
        $complete = true;

        foreach (self::REQUIRED_PARAMETERS as $parameter => $env) {
            $key = substr($parameter, \strlen('auth_client.'));
            $label = sprintf('Konfiguracja %s', $key);

            try {
                $value = $this->parameters->get($parameter);
            } catch (EnvNotFoundException) {
                $results[] = CheckResult::failure($label, sprintf('brak zmiennej środowiskowej (zwykle %s)', $env), sprintf('Ustaw %s w .env.local / sekretach (dane panelu z bazy dostępów Work HUB).', $env));
                $complete = false;
                continue;
            } catch (ParameterNotFoundException) {
                $results[] = CheckResult::failure($label, 'parametr nie istnieje', 'Czy bundle jest zarejestrowany w config/bundles.php?');
                $complete = false;
                continue;
            }

            if (!\is_string($value) || '' === trim($value)) {
                $results[] = CheckResult::failure($label, 'pusta wartość', sprintf('Uzupełnij %s.', $env));
                $complete = false;
                continue;
            }

            $values[$key] = trim($value);
            $results[] = CheckResult::ok($label, match ($key) {
                'client_secret' => 'ustawiony',
                default => $values[$key],
            });
        }

        if (isset($values['panel_id']) && !Uuid::isValid($values['panel_id'])) {
            $results[] = CheckResult::failure('Format panel_id', 'to nie jest UUID', 'AUTH_PANEL_ID to UUID panelu z auth-panelu (nie nazwa ani client_id).');
            $complete = false;
        }

        if (isset($values['base_url']) && str_starts_with($values['base_url'], 'http://') && !$this->isLocalUrl($values['base_url'])) {
            $results[] = CheckResult::warning('AUTH_BASE_URL', 'auth server po HTTP (bez TLS)', 'Poza localhost używaj https://.');
        }

        if (!$complete) {
            return [null, $results];
        }

        /** @var array{base_url: string, panel_id: string, client_id: string, client_secret: string} $values */
        return [$values, $results];
    }

    /**
     * @param array{base_url: string, panel_id: string, client_id: string, client_secret: string} $config
     *
     * @return list<CheckResult>
     */
    private function remoteChecks(array $config, ?string $accessToken): array
    {
        $baseUrl = rtrim($config['base_url'], '/');
        $results = [];

        $jwks = $this->jwksCheck($baseUrl);
        $results[] = $jwks;
        if (CheckStatus::Failure === $jwks->status) {
            $results[] = CheckResult::skipped('Dane klienta (Basic)', 'pominięte — auth server nieosiągalny');

            return $results;
        }

        $results[] = $this->credentialsCheck($baseUrl, $config['client_id'], $config['client_secret']);
        $results[] = $this->mfaSupportCheck($baseUrl);
        $results[] = $this->panelIdCheck($baseUrl, $config, $accessToken);

        return $results;
    }

    private function jwksCheck(string $baseUrl): CheckResult
    {
        $label = 'Auth server osiągalny (JWKS)';

        try {
            $response = $this->httpClient->request('GET', $baseUrl . '/.well-known/jwks.json', ['timeout' => 5]);
            $status = $response->getStatusCode();
            if (200 !== $status) {
                return CheckResult::failure($label, sprintf('HTTP %d z /.well-known/jwks.json', $status), 'Sprawdź AUTH_BASE_URL — musi wskazywać auth server (master), np. ' . Configuration::DEFAULT_BASE_URL . '.');
            }
            $body = $response->toArray(false);
            if (!\is_array($body['keys'] ?? null) || [] === $body['keys']) {
                return CheckResult::failure($label, 'JWKS bez kluczy', 'AUTH_BASE_URL wskazuje serwer, który nie wystawia kluczy JWT.');
            }
        } catch (HttpClientException $e) {
            $this->logger->info('auth-client doctor: JWKS request failed', ['error' => $e->getMessage()]);

            return CheckResult::failure($label, sprintf('brak połączenia z %s', $baseUrl), 'Sprawdź AUTH_BASE_URL, DNS i ruch wychodzący z serwera aplikacji.');
        }

        return CheckResult::ok($label, $baseUrl);
    }

    private function credentialsCheck(string $baseUrl, string $clientId, string $clientSecret): CheckResult
    {
        $label = 'Dane klienta (client_id / client_secret)';

        try {
            $response = $this->httpClient->request('POST', $baseUrl . '/api/auth/backend/introspect', [
                'auth_basic' => [$clientId, $clientSecret],
                'json' => new \stdClass(),
                'timeout' => 5,
            ]);
            $status = $response->getStatusCode();
            $basicChallenge = [] !== ($response->getHeaders(false)['www-authenticate'] ?? []);
        } catch (HttpClientException $e) {
            $this->logger->info('auth-client doctor: introspect probe failed', ['error' => $e->getMessage()]);

            return CheckResult::failure($label, 'błąd połączenia', 'Spróbuj ponownie; jeśli się powtarza — sprawdź AUTH_BASE_URL.');
        }

        return match (true) {
            401 === $status && !$basicChallenge => CheckResult::ok($label, 'auth server przyjął poświadczenia'),
            401 === $status => CheckResult::failure($label, 'auth server odrzucił poświadczenia', 'Popraw AUTH_CLIENT_ID / AUTH_CLIENT_SECRET (dane panelu z bazy dostępów Work HUB; secret pokazywany raz przy tworzeniu klienta).'),
            404 === $status => CheckResult::failure($label, 'brak /api/auth/backend/introspect (HTTP 404)', 'AUTH_BASE_URL nie wskazuje auth servera albo serwer jest za stary.'),
            default => CheckResult::warning($label, sprintf('nieoczekiwany HTTP %d', $status), 'Uruchom ponownie; przy powtórce sprawdź logi auth servera.'),
        };
    }

    private function mfaSupportCheck(string $baseUrl): CheckResult
    {
        $label = 'Auth server obsługuje 2FA (wymagane od bundla 0.7)';

        try {
            $status = $this->httpClient->request('POST', $baseUrl . '/api/auth/backend/login/mfa', ['json' => new \stdClass(), 'timeout' => 5])->getStatusCode();
        } catch (HttpClientException $e) {
            $this->logger->info('auth-client doctor: 2FA probe failed', ['error' => $e->getMessage()]);

            return CheckResult::warning($label, 'nie udało się sprawdzić (błąd połączenia)');
        }

        return 404 === $status
            ? CheckResult::failure($label, 'brak tras 2FA na auth serverze (HTTP 404)', 'Auth server jest starszy niż wymaga bundle — zaktualizuj API Core albo użyj bundla < 0.7.')
            : CheckResult::ok($label);
    }

    /**
     * @param array{base_url: string, panel_id: string, client_id: string, client_secret: string} $config
     */
    private function panelIdCheck(string $baseUrl, array $config, ?string $accessToken): CheckResult
    {
        $label = 'panel_id zgodny z klientem';
        if (null === $accessToken || '' === $accessToken) {
            return CheckResult::skipped($label, 'wymaga sesji użytkownika', 'Uruchom z --access-token=<wartość ciasteczka BEARER po zalogowaniu> — doctor porówna panel klienta z AUTH_PANEL_ID.');
        }

        try {
            $response = $this->httpClient->request('POST', $baseUrl . '/api/auth/backend/introspect', [
                'auth_basic' => [$config['client_id'], $config['client_secret']],
                'json' => ['token' => $accessToken],
                'timeout' => 5,
            ]);
            $status = $response->getStatusCode();
            $body = $response->toArray(false);
        } catch (HttpClientException $e) {
            $this->logger->info('auth-client doctor: panel id probe failed', ['error' => $e->getMessage()]);

            return CheckResult::warning($label, 'błąd połączenia');
        }

        if (200 !== $status) {
            return CheckResult::warning($label, sprintf('introspekcja tokenu: HTTP %d', $status), 401 === $status ? 'Token wygasł — zaloguj się ponownie i podaj świeży BEARER.' : 'User nie ma dostępu do tego panelu albo panel wymaga 2FA.');
        }

        $panelId = \is_string($body['panelId'] ?? null) ? $body['panelId'] : null;
        if (null === $panelId) {
            return CheckResult::warning($label, 'auth server nie zwrócił panelId');
        }

        return 0 === strcasecmp($panelId, $config['panel_id'])
            ? CheckResult::ok($label, $panelId)
            : CheckResult::failure($label, sprintf('klient należy do panelu %s, a AUTH_PANEL_ID = %s', $panelId, $config['panel_id']), 'AUTH_PANEL_ID i AUTH_CLIENT_ID muszą pochodzić z tego samego panelu w auth-panelu.');
    }

    /**
     * @return list<CheckResult>
     */
    private function securityChecks(): array
    {
        $uncovered = [];
        foreach (PublicRoutes::PATHS as $path) {
            $firewall = $this->securityInspector->firewallFor($path);
            $public = null !== $firewall && (!$firewall->securityEnabled || \in_array(self::PUBLIC_ACCESS, $this->securityInspector->accessAttributesFor($path), true));
            if (!$public) {
                $uncovered[] = $path;
            }
        }

        $results = [];
        $results[] = [] === $uncovered
            ? CheckResult::ok('Trasy publiczne bundla (security.yaml)', sprintf('%d tras bez wymogu logowania', \count(PublicRoutes::PATHS)))
            : CheckResult::failure('Trasy publiczne bundla (security.yaml)', 'wymagają logowania: ' . implode(', ', $uncovered), 'Uruchom bin/console auth-client:install (albo dodaj firewall `login` z pattern ' . PublicRoutes::pattern() . ' i security: false).');

        $probe = PublicRoutes::PROTECTED_PROBE_PATH;
        $firewall = $this->securityInspector->firewallFor($probe, 'GET');
        $attributes = $this->securityInspector->accessAttributesFor($probe, 'GET');
        $label = sprintf('Firewall API (%s)', $probe);

        if (null === $firewall || !$firewall->securityEnabled) {
            $results[] = CheckResult::failure($label, 'brak zabezpieczonego firewalla dla ^/api', 'Uruchom bin/console auth-client:install.');
        } elseif (!\in_array(JwtCookieAuthenticator::class, $firewall->authenticators, true)) {
            $results[] = CheckResult::failure($label, sprintf('firewall "%s" bez %s', $firewall->name, JwtCookieAuthenticator::class), 'Dodaj authenticatory bundla do custom_authenticators (auth-client:install pokaże fragment).');
        } elseif ([] === $attributes || \in_array(self::PUBLIC_ACCESS, $attributes, true)) {
            $results[] = CheckResult::warning($label, 'brak reguły access_control wymagającej logowania dla ^/api', 'Dodaj { path: ^/api, roles: IS_AUTHENTICATED_FULLY } na końcu access_control.');
        } else {
            $results[] = CheckResult::ok($label, sprintf('firewall "%s", %s', $firewall->name, implode(', ', $attributes)));
        }

        return $results;
    }

    private function corsCheck(): CheckResult
    {
        $label = 'CORS (front na innym originie)';
        if (!$this->parameters->has('nelmio_cors.defaults')) {
            return CheckResult::warning($label, 'brak NelmioCorsBundle', 'Jeśli front działa pod innym originem: composer require nelmio/cors-bundle i bin/console auth-client:install.');
        }

        $options = $this->effectiveCorsOptions(PublicRoutes::PATHS[0]);
        $problems = [];
        if (true !== ($options['allow_credentials'] ?? false)) {
            $problems[] = 'allow_credentials ≠ true (ciasteczka nie dotrą)';
        }
        if (!$this->corsListContains($options['allow_headers'] ?? [], 'x-device-fp')) {
            $problems[] = 'allow_headers bez X-Device-Fp (preflight auth-client >= 2.2 padnie)';
        }
        if (!$this->corsListContains($options['expose_headers'] ?? [], 'retry-after')) {
            $problems[] = 'expose_headers bez Retry-After (front nie pokaże czasu blokady)';
        }
        $origins = $options['allow_origin'] ?? [];
        if ([] === $origins || [''] === $origins) {
            $problems[] = 'allow_origin pusty (ustaw CORS_ALLOW_ORIGIN)';
        }

        return [] === $problems
            ? CheckResult::ok($label)
            : CheckResult::failure($label, implode('; ', $problems), 'Uruchom bin/console auth-client:install (uzupełni nelmio_cors.yaml).');
    }

    /**
     * @return array<string, mixed>
     */
    private function effectiveCorsOptions(string $path): array
    {
        $defaults = $this->parameters->get('nelmio_cors.defaults');
        $options = \is_array($defaults) ? $defaults : [];

        $map = $this->parameters->has('nelmio_cors.map') ? $this->parameters->get('nelmio_cors.map') : [];
        foreach (\is_array($map) ? $map : [] as $pattern => $pathOptions) {
            if (1 === @preg_match('{' . $pattern . '}i', $path)) {
                return array_merge($options, \is_array($pathOptions) ? $pathOptions : []);
            }
        }

        return $options;
    }

    private function corsListContains(mixed $list, string $header): bool
    {
        if (true === $list) {
            return true; // '*' is normalized by Nelmio to true
        }
        if (!\is_array($list)) {
            return false;
        }

        foreach ($list as $item) {
            if (\is_string($item) && ('*' === $item || 0 === strcasecmp($item, $header))) {
                return true;
            }
        }

        return false;
    }

    private function cookieCheck(): CheckResult
    {
        $label = 'Ciasteczka sesji';
        $sameSite = $this->cookieFactory->sameSite();
        $secure = $this->cookieFactory->isSecure();
        $domain = $this->cookieFactory->cookieDomain();

        $detail = sprintf('secure=%s, same_site=%s, domain=%s', $secure ? 'true' : 'false', $sameSite, $domain ?? '(host API)');

        if ('none' === $sameSite && !$secure) {
            return CheckResult::warning($label, $detail . ' — SameSite=None bez Secure: przeglądarka odrzuci ciasteczka', 'Ustaw auth_client.cookie.secure: true albo same_site: lax (front i API w tej samej domenie).');
        }

        if ('none' === $sameSite && $this->frontIsSameSiteAsApi($domain)) {
            return new CheckResult(CheckStatus::Ok, $label, $detail, 'Front i API są w tej samej domenie — same_site: lax wystarczy (none niepotrzebnie osłabia ochronę przed CSRF).');
        }

        return CheckResult::ok($label, null === $domain ? $detail . ' — gdy front jest na innej subdomenie, ustaw AUTH_COOKIE_DOMAIN (np. .vitkac.com)' : $detail);
    }

    /**
     * True only when BOTH the API host and every allowed front origin can be
     * determined and share the registrable domain. Unknown → false (no hint).
     */
    private function frontIsSameSiteAsApi(?string $cookieDomain): bool
    {
        $apiHost = null !== $cookieDomain ? ltrim($cookieDomain, '.') : $this->routerHost();
        if (null === $apiHost || !$this->parameters->has('nelmio_cors.defaults')) {
            return false;
        }

        $origins = $this->effectiveCorsOptions(PublicRoutes::PATHS[0])['allow_origin'] ?? [];
        if (!\is_array($origins) || [] === $origins) {
            return false;
        }

        foreach ($origins as $origin) {
            $host = \is_string($origin) ? self::hostFromOriginPattern($origin) : null;
            if (null === $host || self::registrableDomain($host) !== self::registrableDomain($apiHost)) {
                return false;
            }
        }

        return true;
    }

    private function routerHost(): ?string
    {
        if (!$this->parameters->has('router.request_context.host')) {
            return null;
        }
        $host = $this->parameters->get('router.request_context.host');

        // 'localhost' is Symfony's default when framework.router.default_uri is not set.
        return \is_string($host) && '' !== $host && 'localhost' !== $host ? $host : null;
    }

    /**
     * Host of a literal origin or of a simple anchored origin regex
     * (`^https://pim\.vitkac\.com$`); anything with real regex syntax → null.
     */
    private static function hostFromOriginPattern(string $origin): ?string
    {
        $literal = str_replace(['\\.', '\\/', '\\-'], ['.', '/', '-'], trim($origin, '^$'));
        if (1 !== preg_match('#^https?://([a-z0-9.-]+)(:\d+)?/?$#i', $literal, $m)) {
            return null;
        }

        return strtolower($m[1]);
    }

    /** Approximation without the public suffix list: the last two labels (vitkac.com), localhost / IP as is. */
    private static function registrableDomain(string $host): string
    {
        $host = strtolower(rtrim($host, '.'));
        if (false !== filter_var($host, \FILTER_VALIDATE_IP) || !str_contains($host, '.')) {
            return $host;
        }
        $labels = explode('.', $host);

        return implode('.', \array_slice($labels, -2));
    }

    private function trustedProxiesCheck(): CheckResult
    {
        $label = 'Trusted proxies (IP usera dla auth servera)';

        return [] === Request::getTrustedProxies()
            ? CheckResult::warning($label, 'brak — auth server dostanie IP proxy/ingressu jako X-Client-Ip', 'Ustaw SYMFONY_TRUSTED_PROXIES=private_ranges (auth-client:install dopisze). Prywatne IP auth server traktuje jak brak nagłówka: historia logowań bez IP usera, limit prób tylko per IP+e-mail.')
            : CheckResult::ok($label, self::summarizeProxies(Request::getTrustedProxies()));
    }

    /**
     * @param array<string> $proxies
     */
    private static function summarizeProxies(array $proxies): string
    {
        // `private_ranges` expands to ~24 subnets — keep the line readable.
        return \count($proxies) <= 3
            ? implode(', ', $proxies)
            : sprintf('%s, … (%d podsieci)', implode(', ', \array_slice($proxies, 0, 2)), \count($proxies));
    }

    private function isLocalUrl(string $url): bool
    {
        $host = parse_url($url, \PHP_URL_HOST);

        return \is_string($host) && (\in_array($host, ['localhost', '127.0.0.1', '::1'], true) || str_ends_with($host, '.localhost') || str_ends_with($host, '.test'));
    }
}
