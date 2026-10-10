<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Doctor\SecurityCoverage;

use Symfony\Bundle\SecurityBundle\Security\FirewallMap;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\AccessMapInterface;

final readonly class FirewallMapSecurityCoverageInspector implements SecurityCoverageInspectorInterface
{
    public function __construct(
        #[Autowire(service: 'security.firewall.map')]
        private FirewallMap $firewallMap,
        #[Autowire(service: 'security.access_map')]
        private AccessMapInterface $accessMap,
    ) {}

    public function firewallFor(string $path, string $method = 'POST'): ?FirewallSnapshot
    {
        $config = $this->firewallMap->getFirewallConfig(Request::create($path, $method));
        if (null === $config) {
            return null;
        }

        return new FirewallSnapshot(
            $config->getName(),
            $config->isSecurityEnabled(),
            array_values(array_map('strval', $config->getAuthenticators())),
        );
    }

    public function accessAttributesFor(string $path, string $method = 'POST'): array
    {
        [$attributes] = $this->accessMap->getPatterns(Request::create($path, $method));

        return array_values(array_map(
            static fn (mixed $attribute): string => \is_scalar($attribute) || $attribute instanceof \Stringable ? (string) $attribute : get_debug_type($attribute),
            $attributes ?? [],
        ));
    }
}
