<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Install;

use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * Trusted proxies, so `Request::getClientIp()` is the end user's IP behind the
 * ingress / Traefik. The bundle forwards it to the auth server as `X-Client-Ip`
 * (login history, per-IP attempt limit). The auth server treats a private /
 * reserved X-Client-Ip like a missing header (API Core decision) — so a
 * cluster where the real IP is lost before the proxy degrades safely.
 *
 * Symfony >= 7.2 reads `SYMFONY_TRUSTED_PROXIES` by default; older versions
 * need `framework.trusted_proxies` pointing at the env.
 */
final class TrustedProxiesConfigurator
{
    public const FRAMEWORK_PATH = 'config/packages/framework.yaml';
    public const ENV_PATH = '.env';
    public const ENV_NAME = 'SYMFONY_TRUSTED_PROXIES';
    public const FRAMEWORK_LINE = "trusted_proxies: '%env(default::SYMFONY_TRUSTED_PROXIES)%'";

    /**
     * @param list<string> $definedEnv names already defined in the running environment
     *
     * @return list<PlannedChange>
     */
    public function plan(string $projectDir, int $symfonyVersionId, array $definedEnv = []): array
    {
        $changes = [];
        $frameworkFile = $projectDir . '/' . self::FRAMEWORK_PATH;
        $frameworkYaml = is_file($frameworkFile) ? (string) file_get_contents($frameworkFile) : null;

        $explicit = null !== $frameworkYaml && $this->hasExplicitTrustedProxies($frameworkYaml);
        if ($explicit) {
            return [PlannedChange::unchanged(self::FRAMEWORK_PATH, 'framework.trusted_proxies ustawione w aplikacji — zostawiam')];
        }

        if ($symfonyVersionId < 70200) {
            if (null === $frameworkYaml || 1 !== preg_match('/^framework:\s*$/m', $frameworkYaml)) {
                $changes[] = PlannedChange::manual(self::FRAMEWORK_PATH, 'Symfony < 7.2 nie czyta SYMFONY_TRUSTED_PROXIES sam — dopisz', "framework:\n    " . self::FRAMEWORK_LINE);
            } else {
                $new = (string) preg_replace('/^framework:\s*$/m', "framework:\n    # Real client IP behind the ingress (auth-client-bundle forwards it as X-Client-Ip).\n    " . self::FRAMEWORK_LINE, $frameworkYaml, 1);
                $changes[] = PlannedChange::modify(self::FRAMEWORK_PATH, 'framework.trusted_proxies z env', $frameworkYaml, $new);
            }
        } else {
            $changes[] = PlannedChange::unchanged(self::FRAMEWORK_PATH, 'Symfony >= 7.2 czyta SYMFONY_TRUSTED_PROXIES automatycznie');
        }

        $changes[] = EnvFile::plan($projectDir, self::ENV_PATH, self::ENV_NAME, 'private_ranges', [
            'Trust X-Forwarded-* from the ingress / Traefik, so the auth server sees the user IP (auth-client-bundle).',
        ], $definedEnv);

        return $changes;
    }

    private function hasExplicitTrustedProxies(string $yaml): bool
    {
        try {
            $parsed = Yaml::parse($yaml);
        } catch (ParseException) {
            return 1 === preg_match('/^\s+trusted_proxies:/m', $yaml);
        }
        if (!\is_array($parsed)) {
            return false;
        }
        foreach ($parsed as $key => $section) {
            $framework = 'framework' === $key ? $section : (\is_string($key) && str_starts_with($key, 'when@') && \is_array($section) ? ($section['framework'] ?? null) : null);
            if (\is_array($framework) && \array_key_exists('trusted_proxies', $framework)) {
                return true;
            }
        }

        return false;
    }
}
