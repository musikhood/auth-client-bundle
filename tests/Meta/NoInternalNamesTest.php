<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Meta;

use PHPUnit\Framework\TestCase;

/**
 * The bundle is public (GitHub / Packagist): no company domains or internal product / repo
 * names in any shipped or versioned file. Same patterns as `scripts/leak-check.mjs` in the
 * auth-client repo; written so they do not match their own source. Generic words that are
 * also internal names elsewhere are not listed (too many false positives) — reviewed by hand.
 */
final class NoInternalNamesTest extends TestCase
{
    private const PATTERNS = [
        '/vitkac\.com/i',
        '/vitkac\.sni\.pl/i',
        '/\bsni\.pl\b/i',
        '/\bmusikhood\.(?!io\b|com\b)\w+/i',
        '/\beditor[_-]v3/i',
        '/\bai[-_ ]panel\b/i',
        '/\bpim[_]frontend\b/i',
        '/\bauth[-]panel/i',
        '/\bAPI\sCore\b/',
    ];

    /** Local / installed / generated — not part of the repo. */
    private const SKIP_DIRS = ['vendor', '.git', '.idea', '.claude', '.phpunit.cache', 'var', 'node_modules'];
    private const SKIP_FILES = ['composer.lock', '.phpunit.result.cache', '.DS_Store'];
    private const SKIP_EXTENSIONS = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'zip', 'gz', 'tgz', 'phar'];

    public function testRepositoryHasNoInternalNames(): void
    {
        $root = \dirname(__DIR__, 2);
        $leaks = [];
        foreach ($this->files($root) as $file) {
            $content = (string) file_get_contents($file);
            foreach (self::PATTERNS as $pattern) {
                if (1 === preg_match($pattern, $content, $match)) {
                    $leaks[] = sprintf('%s: %s', substr($file, \strlen($root) + 1), $match[0]);
                }
            }
        }

        self::assertSame([], $leaks, "Internal names in a public repo — replace them with generic ones (e.g. https://auth.example.com):\n" . implode("\n", $leaks));
    }

    public function testPatternsCatchAPlantedLeak(): void
    {
        // Concatenated so the literal leak exists only at runtime, not in this file.
        $planted = 'see the API ' . 'Core docs at https://auth.vit' . 'kac.com';
        $hits = array_filter(self::PATTERNS, static fn (string $pattern): bool => 1 === preg_match($pattern, $planted));

        self::assertCount(2, $hits);
    }

    /**
     * @return iterable<string>
     */
    private function files(string $dir): iterable
    {
        foreach (scandir($dir) ?: [] as $entry) {
            if ('.' === $entry || '..' === $entry) {
                continue;
            }
            $path = $dir . '/' . $entry;
            if (is_dir($path)) {
                if (!\in_array($entry, self::SKIP_DIRS, true)) {
                    yield from $this->files($path);
                }
                continue;
            }
            if (\in_array($entry, self::SKIP_FILES, true) || \in_array(strtolower(pathinfo($entry, \PATHINFO_EXTENSION)), self::SKIP_EXTENSIONS, true)) {
                continue;
            }
            yield $path;
        }
    }
}
