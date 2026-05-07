<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

/**
 * Mapuje config tree (zob. {@see Configuration}) na parametry kontenera,
 * które services.yaml wstrzykuje do serwisów przez bind.
 */
final class AuthClientExtension extends Extension
{
    /**
     * @param array<int, array<string, mixed>> $configs
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $config = $this->processConfiguration(new Configuration(), $configs);

        $container->setParameter('auth_client.base_url', $config['base_url']);
        $container->setParameter('auth_client.panel_id', $config['panel_id']);
        $container->setParameter('auth_client.client_id', $config['client_id']);
        $container->setParameter('auth_client.client_secret', $config['client_secret']);
        $container->setParameter('auth_client.jwks_cache_ttl', $config['jwks_cache_ttl']);
        $container->setParameter('auth_client.validation_cache_ttl', $config['validation_cache_ttl']);

        $container->setParameter('auth_client.cookie.access_name', $config['cookie']['access_name']);
        $container->setParameter('auth_client.cookie.refresh_name', $config['cookie']['refresh_name']);
        $container->setParameter('auth_client.cookie.path', $config['cookie']['path']);
        // Pusty string traktujemy jako null (host-only). Pomocne gdy
        // konsument przekazuje wartość przez env i nie chce ustawiać domeny.
        $container->setParameter('auth_client.cookie.domain', '' === $config['cookie']['domain'] ? null : $config['cookie']['domain']);
        $container->setParameter('auth_client.cookie.secure', $config['cookie']['secure']);
        $container->setParameter('auth_client.cookie.http_only', $config['cookie']['http_only']);
        $container->setParameter('auth_client.cookie.same_site', $config['cookie']['same_site']);
        $container->setParameter('auth_client.cookie.lifetime', $config['cookie']['lifetime']);

        $container->setParameter('auth_client.circuit_breaker.failure_threshold', $config['circuit_breaker']['failure_threshold']);
        $container->setParameter('auth_client.circuit_breaker.open_seconds', $config['circuit_breaker']['open_seconds']);

        $container->setParameter('auth_client.http.timeout', $config['http']['timeout']);
        $container->setParameter('auth_client.http.max_duration', $config['http']['max_duration']);

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yaml');
    }

    public function getAlias(): string
    {
        return 'auth_client';
    }
}
