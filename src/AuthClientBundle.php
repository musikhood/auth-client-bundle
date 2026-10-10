<?php

declare(strict_types=1);

namespace Musikhood\AuthClient;

use Musikhood\AuthClient\DependencyInjection\Compiler\EnsurePanelUserRepositoryPass;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class AuthClientBundle extends Bundle
{
    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        // Runs after standard autowiring, so it sees the application's own
        // user repository alias; without one the stateless built-in is used.
        $container->addCompilerPass(
            new EnsurePanelUserRepositoryPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            -100,
        );
    }
}
