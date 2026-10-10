<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Functional;

use Musikhood\AuthClient\AuthClientBundle;
use Musikhood\AuthClient\Install\SecurityConfigurator;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Yaml\Yaml;

/**
 * Minimal application: FrameworkBundle + SecurityBundle + the bundle, with the
 * security.yaml that `auth-client:install` generates and NO user repository
 * (stateless default mode).
 */
final class TestKernel extends Kernel
{
    use MicroKernelTrait;

    public function __construct(private readonly string $projectDir, private readonly bool $withBundleConfig = true)
    {
        parent::__construct('test', false);
    }

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new SecurityBundle();
        yield new AuthClientBundle();
    }

    public function getProjectDir(): string
    {
        return $this->projectDir;
    }

    public function getCacheDir(): string
    {
        return $this->projectDir . '/var/cache';
    }

    public function getLogDir(): string
    {
        return $this->projectDir . '/var/log';
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'secret' => 'test',
            'test' => true,
            'http_method_override' => false,
            'handle_all_throwables' => true,
            'php_errors' => ['log' => true],
        ]);

        $security = Yaml::parse(SecurityConfigurator::template());
        \assert(\is_array($security));
        $container->extension('security', $security['security']);

        if (!$this->withBundleConfig) {
            // No config/packages/auth_client.yaml at all: everything from env defaults.
            return;
        }

        // The four values the recipe maps from env — nothing else.
        $container->extension('auth_client', [
            'base_url' => 'https://auth.example',
            'panel_id' => '0b5d8f6e-6a8f-4a5e-9a0c-1f2e3d4c5b6a',
            'client_id' => 'panel-backend',
            'client_secret' => 'secret',
        ]);
    }
}
