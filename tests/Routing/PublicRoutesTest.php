<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Routing;

use Musikhood\AuthClient\Routing\PublicRoutes;
use PHPUnit\Framework\TestCase;

final class PublicRoutesTest extends TestCase
{
    public function testPatternMatchesExactlyThePublicPaths(): void
    {
        $regex = '{' . PublicRoutes::pattern() . '}';

        foreach (PublicRoutes::PATHS as $path) {
            self::assertSame(1, preg_match($regex, $path), $path);
        }
        foreach (['/api/login/mfa/extra', '/api/loginx', '/api/session/mfa2', '/api/mfa/enrollment/start', '/api/v1/user/me', '/api/token/refreshx'] as $path) {
            self::assertSame(0, preg_match($regex, $path), $path);
        }
    }

    public function testEveryBundleControllerRouteIsClassified(): void
    {
        // Every #[Route] of the bundle is either public or the protected /me.
        $paths = [];
        foreach (glob(__DIR__ . '/../../src/Controller/*Controller.php') ?: [] as $file) {
            preg_match_all("/#\\[Route\\('([^']+)'/", (string) file_get_contents($file), $m);
            array_push($paths, ...$m[1]);
        }

        self::assertNotEmpty($paths);
        foreach ($paths as $path) {
            self::assertTrue(PublicRoutes::isPublic($path) || PublicRoutes::PROTECTED_PROBE_PATH === $path, $path . ' is neither public nor the protected probe');
        }
        foreach (PublicRoutes::PATHS as $path) {
            self::assertContains($path, $paths, $path . ' has no controller');
        }
    }
}
