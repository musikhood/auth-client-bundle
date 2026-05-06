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

        // Compiler pass biegnie po standardowym autowiringu, więc zobaczy alias
        // konsumenta jeśli istnieje. Brak aliasu => rejestrujemy stub żeby
        // `composer require` + post-install `cache:clear` przeszło, a runtime
        // wywalił czytelny komunikat przy pierwszym wywołaniu auth flow.
        $container->addCompilerPass(
            new EnsurePanelUserRepositoryPass(),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
            -100,
        );
    }
}
