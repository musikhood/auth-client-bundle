<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Drzewo konfiguracyjne bundla. Konsument konfiguruje to przez
 * config/packages/auth_client.yaml.
 */
final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('auth_client');
        /** @phpstan-ignore-next-line — getRootNode() returns NodeDefinition&ParentNodeDefinitionInterface at runtime */
        $rootNode = $treeBuilder->getRootNode();

        $rootNode
            ->children()
                ->scalarNode('base_url')
                    ->isRequired()
                    ->cannotBeEmpty()
                    ->info('Auth server base URL, np. https://auth.example.com')
                ->end()
                ->scalarNode('panel_id')
                    ->isRequired()
                    ->cannotBeEmpty()
                    ->info('Identyfikator panelu (UUID) wystawiony przez auth server.')
                ->end()
                ->scalarNode('client_id')
                    ->isRequired()
                    ->cannotBeEmpty()
                    ->info('Backend client_id do HTTP Basic auth na endpointach /api/auth/backend/*.')
                ->end()
                ->scalarNode('client_secret')
                    ->isRequired()
                    ->cannotBeEmpty()
                    ->info('Backend client_secret do HTTP Basic auth na endpointach /api/auth/backend/*.')
                ->end()
                ->integerNode('jwks_cache_ttl')
                    ->defaultValue(3600)
                    ->min(0)
                    ->info('TTL cache dokumentu JWKS (sekundy).')
                ->end()
                ->integerNode('validation_cache_ttl')
                    ->defaultValue(30)
                    ->min(0)
                    ->info('TTL cache wyniku introspekcji /me per user (sekundy).')
                ->end()
                ->arrayNode('cookie')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('access_name')->defaultValue('BEARER')->cannotBeEmpty()->end()
                        ->scalarNode('refresh_name')->defaultValue('refresh_token')->cannotBeEmpty()->end()
                        ->scalarNode('path')->defaultValue('/')->cannotBeEmpty()->end()
                        ->booleanNode('secure')->defaultTrue()->end()
                        ->booleanNode('http_only')->defaultTrue()->end()
                        ->enumNode('same_site')
                            ->values(['lax', 'strict', 'none'])
                            ->defaultValue('lax')
                        ->end()
                        ->integerNode('lifetime')
                            ->defaultValue(2592000)
                            ->min(1)
                            ->info('Czas życia ciasteczek w sekundach. Powinien odpowiadać TTL refresh_token na auth serverze.')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('circuit_breaker')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->integerNode('failure_threshold')->defaultValue(3)->min(1)->end()
                        ->integerNode('open_seconds')->defaultValue(60)->min(1)->end()
                    ->end()
                ->end()
                ->arrayNode('http')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->floatNode('timeout')->defaultValue(5.0)->min(0.1)->end()
                        ->floatNode('max_duration')->defaultValue(10.0)->min(0.1)->end()
                    ->end()
                ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
