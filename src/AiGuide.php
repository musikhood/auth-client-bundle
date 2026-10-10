<?php

declare(strict_types=1);

namespace Musikhood\AuthClient;

/**
 * Location of AI_INTEGRATION.md — the integration guide for AI agents shipped with the
 * bundle (repo root, so it lands in vendor/musikhood/auth-client-bundle/). Printed by
 * `auth-client:install` and `auth-client:doctor`.
 */
final class AiGuide
{
    public const FILE = 'AI_INTEGRATION.md';

    public static function absolutePath(): string
    {
        return \dirname(__DIR__) . '/' . self::FILE;
    }

    /** Path relative to the project dir when the bundle lives inside it (vendor/…). */
    public static function displayPath(string $projectDir): string
    {
        $path = self::absolutePath();
        $prefix = rtrim($projectDir, '/') . '/';

        return str_starts_with($path, $prefix) ? substr($path, \strlen($prefix)) : $path;
    }

    public static function line(string $projectDir): string
    {
        return sprintf('Instrukcja integracji (dla agenta AI): %s', self::displayPath($projectDir));
    }
}
