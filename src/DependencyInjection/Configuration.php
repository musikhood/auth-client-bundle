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
        // getRootNode() is statically typed as NodeDefinition, but at runtime is
        // ArrayNodeDefinition exposing children()/scalarNode(). The fluent chain
        // below trips phpstan-symfony's NodeBuilder generics — ignored in phpstan.neon.dist.
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
                        ->scalarNode('domain')
                            ->defaultNull()
                            ->info('Domena ciasteczka. Null lub puste = host bieżącego żądania (default). Ustaw np. .example.com żeby ciasteczka działały na wszystkich subdomenach (front i backend pod różnymi subdomenami tej samej parent domain).')
                        ->end()
                        ->booleanNode('secure')->defaultTrue()->end()
                        ->booleanNode('http_only')->defaultTrue()->end()
                        ->enumNode('same_site')
                            ->values(['lax', 'strict', 'none'])
                            ->defaultValue('lax')
                        ->end()
                        // TTL ciasteczek jest hardcoded w AuthCookieFactory (BEARER 15 min, refresh_token 30 dni)
                        // i dopasowany do typowego deploymentu auth servera. Nie wystawiamy go jako konfigurowalny,
                        // żeby uniknąć dryfu między paczką a auth serverem.
                    ->end()
                ->end()
                ->arrayNode('api_token')
                    ->addDefaultsIfNotSet()
                    ->info('Per-user-per-panel API token (drugi sposób autoryzacji obok JWT-cookie).')
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultTrue()
                            ->info('Czy ApiTokenAuthenticator jest aktywny. Sam authenticator i tak reaguje tylko gdy nagłówek jest obecny.')
                        ->end()
                        ->scalarNode('header')
                            ->defaultValue('X-Api-Token')
                            ->cannotBeEmpty()
                            ->info('Nazwa nagłówka niosącego raw token.')
                        ->end()
                        ->integerNode('cache_ttl')
                            ->defaultValue(0)
                            ->min(0)
                            ->info('TTL cache wyniku introspekcji tokenu (sekundy). Default 0 = bez cache → natychmiastowa rewokacja.')
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
