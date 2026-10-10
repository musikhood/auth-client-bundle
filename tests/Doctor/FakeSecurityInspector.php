<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Doctor;

use Musikhood\AuthClient\Doctor\SecurityCoverage\FirewallSnapshot;
use Musikhood\AuthClient\Doctor\SecurityCoverage\SecurityCoverageInspectorInterface;
use Musikhood\AuthClient\Routing\PublicRoutes;
use Musikhood\AuthClient\Security\JwtCookieAuthenticator;

final readonly class FakeSecurityInspector implements SecurityCoverageInspectorInterface
{
    public function __construct(private bool $publicRoutesCovered = true) {}

    public function firewallFor(string $path, string $method = 'POST'): ?FirewallSnapshot
    {
        return PublicRoutes::isPublic($path) && $this->publicRoutesCovered
            ? new FirewallSnapshot('login', false, [])
            : new FirewallSnapshot('api', true, [JwtCookieAuthenticator::class]);
    }

    public function accessAttributesFor(string $path, string $method = 'POST'): array
    {
        return PublicRoutes::isPublic($path) && $this->publicRoutesCovered ? ['PUBLIC_ACCESS'] : ['IS_AUTHENTICATED_FULLY'];
    }
}
