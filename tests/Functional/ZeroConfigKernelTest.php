<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Functional;

use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Musikhood\AuthClient\Cookie\AuthCookieFactory;
use Musikhood\AuthClient\DependencyInjection\Configuration;
use Musikhood\AuthClient\Doctor\SecurityCoverage\SecurityCoverageInspectorInterface;
use Musikhood\AuthClient\Routing\PublicRoutes;
use Musikhood\AuthClient\Security\JwtCookieAuthenticator;
use Musikhood\AuthClient\Security\Stateless\StatelessPanelUserRepository;
use Musikhood\AuthClient\Tests\Install\InstallTestCase;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class ZeroConfigKernelTest extends InstallTestCase
{
    private ?TestKernel $kernel = null;

    /** @var callable|null exception handler active before the kernel booted */
    private $previousExceptionHandler;

    protected function setUp(): void
    {
        parent::setUp();
        $this->previousExceptionHandler = set_exception_handler(null);
        set_exception_handler($this->previousExceptionHandler);
    }

    protected function tearDown(): void
    {
        $this->kernel?->shutdown();
        // FrameworkBundle::boot() installs Symfony's ErrorHandler — restore PHPUnit's.
        for ($i = 0; $i < 10; ++$i) {
            $current = set_exception_handler(null);
            set_exception_handler($current);
            if ($current === $this->previousExceptionHandler) {
                break;
            }
            restore_exception_handler();
        }
        parent::tearDown();
    }

    public function testWithoutUserRepositoryTheStatelessOneIsUsed(): void
    {
        $container = $this->boot()->getContainer()->get('test.service_container');
        \assert($container instanceof \Symfony\Component\DependencyInjection\ContainerInterface);

        self::assertInstanceOf(StatelessPanelUserRepository::class, $container->get(PanelUserRepositoryInterface::class));
    }

    public function testDefaultsNeedOnlyTheFourPanelValues(): void
    {
        $container = $this->boot()->getContainer()->get('test.service_container');
        \assert($container instanceof \Symfony\Component\DependencyInjection\ContainerInterface);

        $cookies = $container->get(AuthCookieFactory::class);
        \assert($cookies instanceof AuthCookieFactory);
        self::assertTrue($cookies->isSecure());
        self::assertSame('lax', $cookies->sameSite(), 'BC with 0.7: same-site front/API (subdomains of one domain) work with lax');
        self::assertNull($cookies->cookieDomain(), 'AUTH_COOKIE_DOMAIN unset → host-only');
        self::assertSame('https://editor-v3-backend.vitkac.com', Configuration::DEFAULT_BASE_URL);
    }

    public function testWithoutAnyBundleConfigEverythingComesFromEnv(): void
    {
        $_SERVER['AUTH_PANEL_ID'] = '0b5d8f6e-6a8f-4a5e-9a0c-1f2e3d4c5b6a';
        $_SERVER['AUTH_CLIENT_ID'] = 'panel-backend';
        $_SERVER['AUTH_CLIENT_SECRET'] = 'secret';
        unset($_SERVER['AUTH_BASE_URL']);

        try {
            $this->kernel = new TestKernel($this->projectDir, withBundleConfig: false);
            $this->kernel->boot();
            $container = $this->kernel->getContainer();

            self::assertSame('https://editor-v3-backend.vitkac.com', $container->getParameter('auth_client.base_url'), 'AUTH_BASE_URL unset → production');
            self::assertSame('panel-backend', $container->getParameter('auth_client.client_id'));

            $_SERVER['AUTH_BASE_URL'] = 'https://auth-dev.example';
            $this->kernel->shutdown();
            $this->kernel = new TestKernel($this->projectDir, withBundleConfig: false);
            $this->kernel->boot();
            self::assertSame('https://auth-dev.example', $this->kernel->getContainer()->getParameter('auth_client.base_url'));
        } finally {
            unset($_SERVER['AUTH_PANEL_ID'], $_SERVER['AUTH_CLIENT_ID'], $_SERVER['AUTH_CLIENT_SECRET'], $_SERVER['AUTH_BASE_URL']);
        }
    }

    public function testGeneratedSecurityConfigCoversEveryBundleRoute(): void
    {
        $container = $this->boot()->getContainer()->get('test.service_container');
        \assert($container instanceof \Symfony\Component\DependencyInjection\ContainerInterface);
        $inspector = $container->get(SecurityCoverageInspectorInterface::class);
        \assert($inspector instanceof SecurityCoverageInspectorInterface);

        foreach (PublicRoutes::PATHS as $path) {
            $firewall = $inspector->firewallFor($path);
            self::assertNotNull($firewall, $path);
            self::assertFalse($firewall->securityEnabled, $path);
        }

        $api = $inspector->firewallFor(PublicRoutes::PROTECTED_PROBE_PATH, 'GET');
        self::assertNotNull($api);
        self::assertTrue($api->securityEnabled);
        self::assertContains(JwtCookieAuthenticator::class, $api->authenticators);
        self::assertSame(['IS_AUTHENTICATED_FULLY'], $inspector->accessAttributesFor(PublicRoutes::PROTECTED_PROBE_PATH, 'GET'));
        self::assertSame(['IS_AUTHENTICATED_FULLY'], $inspector->accessAttributesFor('/api/login/mfa/extra'));
    }

    public function testDoctorCommandRunsAgainstTheLiveConfiguration(): void
    {
        $kernel = $this->boot();
        $container = $kernel->getContainer()->get('test.service_container');
        \assert($container instanceof \Symfony\Component\DependencyInjection\ContainerInterface);
        $container->set('http_client', new MockHttpClient(static function (string $method, string $url): MockResponse {
            return match ((string) parse_url($url, \PHP_URL_PATH)) {
                '/.well-known/jwks.json' => new MockResponse('{"keys":[{"kid":"k"}]}'),
                '/api/auth/backend/introspect' => new MockResponse('{"error":"Nie przekazano tokenu."}', ['http_code' => 401]),
                default => new MockResponse('{}', ['http_code' => 401]),
            };
        }));

        $tester = new CommandTester((new Application($kernel))->find('auth-client:doctor'));
        $exit = $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertSame(0, $exit, $display);
        self::assertStringContainsString('✔ Trasy publiczne bundla', $display);
        self::assertStringContainsString('✔ Dane klienta', $display);
        self::assertStringNotContainsString('secret', strtolower(str_replace(['client_secret', 'AUTH_CLIENT_SECRET'], '', $display)));
    }

    public function testInstallDryRunWritesNothing(): void
    {
        $kernel = $this->boot();
        $this->put('config/packages/security.yaml', $this->fixture('security.stock.yaml'));
        $before = $this->snapshotWithoutVar();

        $tester = new CommandTester((new Application($kernel))->find('auth-client:install'));
        $tester->execute(['--dry-run' => true, '--no-doctor' => true]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('[zmienię] config/packages/security.yaml', $display);
        self::assertStringContainsString('dry-run', $display);
        self::assertSame($before, $this->snapshotWithoutVar());
    }

    public function testInstallWithYesWritesAndIsIdempotent(): void
    {
        $kernel = $this->boot();
        $this->put('config/packages/security.yaml', $this->fixture('security.stock.yaml'));
        $application = new Application($kernel);

        $first = new CommandTester($application->find('auth-client:install'));
        $first->execute(['--yes' => true, '--no-doctor' => true], ['interactive' => false]);
        self::assertStringContainsString('Zapisano', $first->getDisplay());

        $second = new CommandTester($application->find('auth-client:install'));
        $second->execute(['--yes' => true, '--no-doctor' => true], ['interactive' => false]);
        self::assertStringContainsString('Brak zmian do zapisania', $second->getDisplay());
    }

    private function boot(): TestKernel
    {
        $this->kernel = new TestKernel($this->projectDir);
        $this->kernel->boot();

        return $this->kernel;
    }

    /**
     * @return array<string, string>
     */
    private function snapshotWithoutVar(): array
    {
        return array_filter($this->snapshot(), static fn (string $path): bool => !str_starts_with($path, 'var/'), \ARRAY_FILTER_USE_KEY);
    }
}
