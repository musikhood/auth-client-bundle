<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Install;

/**
 * Appends a non-secret default to `.env` (committed defaults, as Symfony Flex
 * does) — never overwrites an existing key, never touches `.env.local`, and
 * skips variables the running environment already defines (.env.local,
 * .env.<env>.local, real env / k8s secrets).
 */
final class EnvFile
{
    /**
     * @param list<string> $comments
     * @param list<string> $definedEnv names already defined in the running environment
     */
    public static function plan(string $projectDir, string $path, string $name, string $value, array $comments = [], array $definedEnv = []): PlannedChange
    {
        if (\in_array($name, $definedEnv, true)) {
            return PlannedChange::unchanged($path, sprintf('%s już ustawione w środowisku', $name));
        }

        $file = $projectDir . '/' . $path;
        $old = is_file($file) ? (string) file_get_contents($file) : null;

        if (null !== $old && 1 === preg_match('/^\s*(export\s+)?' . preg_quote($name, '/') . '=/m', $old)) {
            return PlannedChange::unchanged($path, sprintf('%s już zdefiniowane', $name));
        }

        $block = '';
        foreach ($comments as $comment) {
            $block .= '# ' . $comment . "\n";
        }
        $block .= $name . '=' . $value . "\n";

        if (null === $old) {
            return PlannedChange::create($path, sprintf('%s=%s', $name, $value), $block);
        }

        $separator = '' === $old || str_ends_with($old, "\n") ? "\n" : "\n\n";

        return PlannedChange::modify($path, sprintf('%s=%s', $name, $value), $old, $old . $separator . $block);
    }
}
