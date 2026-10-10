<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Doctor\SecurityCoverage;

/**
 * Answers "which firewall and which access_control rule handle this path" from
 * the LIVE security configuration (after cache:clear), not from the YAML file.
 */
interface SecurityCoverageInspectorInterface
{
    public function firewallFor(string $path, string $method = 'POST'): ?FirewallSnapshot;

    /**
     * @return list<string> attributes of the first matching access_control rule ([] = no rule)
     */
    public function accessAttributesFor(string $path, string $method = 'POST'): array;
}
