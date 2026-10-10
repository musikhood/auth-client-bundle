<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Install;

/**
 * Imports the bundle's routes (`config/routes/auth_client.yaml`) unless the
 * application already imports them somewhere (Flex recipe or by hand).
 */
final class RoutesConfigurator
{
    public const PATH = 'config/routes/auth_client.yaml';

    public const CONTENT = <<<'YAML'
        auth_client:
            resource: '@AuthClientBundle/Resources/config/routes.yaml'

        YAML;

    public function plan(string $projectDir): PlannedChange
    {
        $candidates = array_merge(
            glob($projectDir . '/config/routes/*.{yaml,yml,php,xml}', \GLOB_BRACE) ?: [],
            glob($projectDir . '/config/routes.{yaml,yml,php,xml}', \GLOB_BRACE) ?: [],
        );
        foreach ($candidates as $file) {
            if (str_contains((string) file_get_contents($file), '@AuthClientBundle')) {
                return PlannedChange::unchanged(substr($file, \strlen($projectDir) + 1), 'trasy bundla już zaimportowane');
            }
        }

        return PlannedChange::create(self::PATH, 'import tras bundla (/api/login, 2FA, refresh, /api/v1/user/me…)', self::CONTENT);
    }
}
