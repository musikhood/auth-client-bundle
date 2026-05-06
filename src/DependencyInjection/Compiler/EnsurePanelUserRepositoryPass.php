<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\DependencyInjection\Compiler;

use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Musikhood\AuthClient\Security\MissingPanelUserRepository;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

/**
 * Jeśli konsument nie podpiął jeszcze swojego repozytorium użytkownika
 * (przez `#[AsAlias]` albo alias w `services.yaml`), rejestrujemy stub
 * {@see MissingPanelUserRepository}. Dzięki temu `cache:clear` zaraz po
 * `composer require` przechodzi bez błędu autowire, a jasny komunikat
 * pojawi się dopiero przy pierwszym realnym użyciu auth flow.
 *
 * Stub jest wymieniany na właściwą implementację automatycznie po
 * dodaniu `#[AsAlias]` lub aliasu w `services.yaml` — Symfony przy
 * następnym `cache:clear` widzi prawdziwy alias i ten compiler pass
 * (priority po standardowym autowiringu) nie nadpisze go ponownie.
 */
final class EnsurePanelUserRepositoryPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if ($container->has(PanelUserRepositoryInterface::class)) {
            return;
        }

        $container->setDefinition(
            PanelUserRepositoryInterface::class,
            (new Definition(MissingPanelUserRepository::class))->setPublic(false),
        );
    }
}
