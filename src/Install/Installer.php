<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Install;

/**
 * Plans and applies `auth-client:install`. Planning reads files only; apply()
 * writes Create/Modify changes and never touches Manual/Unchanged ones.
 */
final readonly class Installer
{
    /** @var array<string, string> env => committed default in .env (empty = to be filled in .env.local / secrets) */
    public const PANEL_ENV = [
        'AUTH_BASE_URL' => 'https://editor-v3-backend.vitkac.com',
        'AUTH_PANEL_ID' => '',
        'AUTH_CLIENT_ID' => '',
        'AUTH_CLIENT_SECRET' => '',
    ];

    public function __construct(
        private SecurityConfigurator $security = new SecurityConfigurator(),
        private CorsConfigurator $cors = new CorsConfigurator(),
        private TrustedProxiesConfigurator $trustedProxies = new TrustedProxiesConfigurator(),
        private RoutesConfigurator $routes = new RoutesConfigurator(),
    ) {}

    /**
     * @param list<string> $definedEnv env names already defined in the running environment
     *
     * @return list<PlannedChange>
     */
    public function plan(string $projectDir, bool $nelmioInstalled, int $symfonyVersionId, array $definedEnv = []): array
    {
        $changes = [];
        foreach (self::PANEL_ENV as $name => $default) {
            $changes[] = EnvFile::plan($projectDir, '.env', $name, $default, 'AUTH_BASE_URL' === $name
                ? ['auth-client-bundle: auth server (API Core). Panel values below come from the Work HUB access base',
                    '(secret_to_env) — set them in .env.local / k8s secrets, never commit the secret.']
                : [], $definedEnv);
        }
        $changes[] = $this->routes->plan($projectDir);
        $changes[] = $this->security->plan($projectDir);

        $cors = $this->cors->plan($projectDir, $nelmioInstalled);
        $changes[] = $cors;
        if ($nelmioInstalled && ChangeKind::Create === $cors->kind) {
            // Nelmio installed without its recipe: the generated file needs the origin env.
            $changes[] = EnvFile::plan($projectDir, '.env', 'CORS_ALLOW_ORIGIN', "'^https?://(localhost|127\\.0\\.0\\.1)(:[0-9]+)?$'", [
                'Origins allowed to call the API with cookies (regex). Production: e.g. ^https://panel\\.vitkac\\.com$',
            ], $definedEnv);
        }

        array_push($changes, ...$this->trustedProxies->plan($projectDir, $symfonyVersionId, $definedEnv));

        return self::mergeSameFile($changes);
    }

    /**
     * @param list<PlannedChange> $changes
     */
    public function apply(string $projectDir, array $changes): void
    {
        foreach ($changes as $change) {
            if (!$change->writes() || null === $change->newContent) {
                continue;
            }
            $file = $projectDir . '/' . $change->path;
            $dir = \dirname($file);
            if (!is_dir($dir) && !mkdir($dir, 0o775, true) && !is_dir($dir)) {
                throw new \RuntimeException(sprintf('Nie można utworzyć katalogu %s.', $dir));
            }
            if (false === file_put_contents($file, $change->newContent)) {
                throw new \RuntimeException(sprintf('Nie można zapisać %s.', $file));
            }
        }
    }

    /**
     * Two planned edits of the same file (e.g. two .env keys) are chained so
     * the second one builds on the first instead of overwriting it.
     *
     * @param list<PlannedChange> $changes
     *
     * @return list<PlannedChange>
     */
    private static function mergeSameFile(array $changes): array
    {
        $result = [];
        $writerIndex = [];
        foreach ($changes as $change) {
            if (!$change->writes() || !isset($writerIndex[$change->path])) {
                if ($change->writes()) {
                    $writerIndex[$change->path] = \count($result);
                }
                $result[] = $change;
                continue;
            }

            $previous = $result[$writerIndex[$change->path]];
            $base = (string) ($change->oldContent ?? '');
            $addition = (string) $change->newContent;
            $appended = str_starts_with($addition, $base) ? substr($addition, \strlen($base)) : $addition;
            $appended = ltrim($appended, "\n");
            $previousContent = (string) $previous->newContent;
            // Keys of one group stay together; a new commented block gets a blank line before it.
            $separator = str_ends_with($previousContent, "\n") ? (str_starts_with($appended, '#') ? "\n" : '') : "\n";
            $merged = $previousContent . $separator . $appended;

            $result[$writerIndex[$change->path]] = new PlannedChange(
                $previous->kind,
                $previous->path,
                $previous->summary . '; ' . $change->summary,
                $previous->oldContent,
                $merged,
            );
        }

        return $result;
    }
}
