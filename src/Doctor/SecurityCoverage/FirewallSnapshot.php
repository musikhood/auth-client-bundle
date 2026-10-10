<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Doctor\SecurityCoverage;

/**
 * What the doctor needs to know about the firewall that handles a path.
 */
final readonly class FirewallSnapshot
{
    /**
     * @param list<string> $authenticators authenticator ids (custom authenticators = class names)
     */
    public function __construct(
        public string $name,
        public bool $securityEnabled,
        public array $authenticators,
    ) {}
}
