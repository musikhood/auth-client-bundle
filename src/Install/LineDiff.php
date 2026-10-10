<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Install;

/**
 * Minimal line diff (LCS) for showing config changes in the console. Config
 * files are small, so the O(n*m) table is fine.
 */
final class LineDiff
{
    /**
     * @return list<string> lines prefixed with '  ', '- ' or '+ ' (unchanged lines far from a change are collapsed)
     */
    public static function render(string $old, string $new, int $context = 2): array
    {
        $a = explode("\n", rtrim($old, "\n"));
        $b = explode("\n", rtrim($new, "\n"));
        $n = \count($a);
        $m = \count($b);

        $lcs = array_fill(0, $n + 1, array_fill(0, $m + 1, 0));
        for ($i = $n - 1; $i >= 0; --$i) {
            for ($j = $m - 1; $j >= 0; --$j) {
                $lcs[$i][$j] = $a[$i] === $b[$j] ? $lcs[$i + 1][$j + 1] + 1 : max($lcs[$i + 1][$j], $lcs[$i][$j + 1]);
            }
        }

        /** @var list<array{0: string, 1: string}> $ops */
        $ops = [];
        $i = $j = 0;
        while ($i < $n || $j < $m) {
            if ($i < $n && $j < $m && $a[$i] === $b[$j]) {
                $ops[] = [' ', $a[$i]];
                ++$i;
                ++$j;
            } elseif ($i < $n && ($j >= $m || $lcs[$i + 1][$j] >= $lcs[$i][$j + 1])) {
                $ops[] = ['-', $a[$i]];
                ++$i;
            } else {
                $ops[] = ['+', $b[$j]];
                ++$j;
            }
        }

        $changed = [];
        foreach ($ops as $index => [$type]) {
            if (' ' !== $type) {
                $changed[] = $index;
            }
        }

        $lines = [];
        $lastPrinted = -1;
        foreach ($ops as $index => [$type, $text]) {
            $near = false;
            foreach ($changed as $c) {
                if (abs($c - $index) <= $context) {
                    $near = true;
                    break;
                }
            }
            if (!$near) {
                continue;
            }
            if ($lastPrinted >= 0 && $index > $lastPrinted + 1) {
                $lines[] = '  …';
            }
            $lines[] = (' ' === $type ? '  ' : $type . ' ') . $text;
            $lastPrinted = $index;
        }

        return $lines;
    }
}
