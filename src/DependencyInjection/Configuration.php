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
                // Zero-config: every value comes from env by default, so the bundle
                // works (and the container compiles) without config/packages/auth_client.yaml.
                // A missing env fails only at runtime — `auth-client:doctor` reports it.
                ->scalarNode('base_url')
                    ->defaultValue('%env(AUTH_BASE_URL)%')
                    ->cannotBeEmpty()
                    ->info('Adres auth servera. Domyślnie env AUTH_BASE_URL (wymagany — wartość z bazy dostępów).')
                ->end()
                ->scalarNode('panel_id')
                    ->defaultValue('%env(AUTH_PANEL_ID)%')
                    ->cannotBeEmpty()
                    ->info('Identyfikator panelu (UUID) wystawiony przez auth server. Domyślnie env AUTH_PANEL_ID.')
                ->end()
                ->scalarNode('client_id')
                    ->defaultValue('%env(AUTH_CLIENT_ID)%')
                    ->cannotBeEmpty()
                    ->info('Backend client_id do HTTP Basic auth na endpointach /api/auth/backend/*. Domyślnie env AUTH_CLIENT_ID.')
                ->end()
                ->scalarNode('client_secret')
                    ->defaultValue('%env(AUTH_CLIENT_SECRET)%')
                    ->cannotBeEmpty()
                    ->info('Backend client_secret do HTTP Basic auth na endpointach /api/auth/backend/*. Domyślnie env AUTH_CLIENT_SECRET.')
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
                            // Optional env: empty / unset = host-only cookie.
                            ->defaultValue('%env(default::AUTH_COOKIE_DOMAIN)%')
                            ->info('Domena ciasteczka. Null lub puste = host bieżącego żądania (default). Ustaw np. .example.com żeby ciasteczka działały na wszystkich subdomenach (front i backend pod różnymi subdomenami tej samej parent domain).')
                        ->end()
                        ->booleanNode('secure')->defaultTrue()->end()
                        ->booleanNode('http_only')->defaultTrue()->end()
                        ->enumNode('same_site')
                            ->values(['lax', 'strict', 'none'])
                            // SameSite is evaluated per registrable domain ("site"), not per host:
                            // a front and an API on subdomains of the same domain
                            // (panel.example.com / panel-api.example.com, or localhost on different
                            // ports) are same-site and work with `lax`. Use `none` only when the
                            // front and the API live on different domains (requires secure=true).
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
                ->arrayNode('device_binding')
                    ->addDefaultsIfNotSet()
                    ->info('Wiązanie sesji z urządzeniem (2FA, auth server >= 2FA release, auth-client >= 2.2).')
                    ->children()
                        ->enumNode('mode')
                            ->values(['off', 'observe', 'enforce'])
                            ->defaultValue('observe')
                            ->info('Porównanie claimu `fph` z nagłówkiem X-Device-Fp: off = brak, observe = tylko log, enforce = 401 device_mismatch_recheck.')
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
