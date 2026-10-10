<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\DependencyInjection\Compiler;

use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Musikhood\AuthClient\Security\Stateless\StatelessPanelUserRepository;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Picks the user repository:
 *   - the application registered its own {@see PanelUserRepositoryInterface}
 *     (`#[AsAlias]` / alias in services.yaml — e.g. a Doctrine mirror table,
 *     like PIM) → used as is;
 *   - otherwise → the built-in stateless repository (no entity, no table):
 *     {@see StatelessPanelUserRepository}.
 *
 * Runs after standard autowiring, so it sees the application's alias.
 */
final class EnsurePanelUserRepositoryPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if ($container->has(PanelUserRepositoryInterface::class)) {
            return;
        }

        $container->setAlias(PanelUserRepositoryInterface::class, StatelessPanelUserRepository::class)->setPublic(false);
    }
}
