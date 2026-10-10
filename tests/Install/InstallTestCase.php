<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Install;

use PHPUnit\Framework\TestCase;

abstract class InstallTestCase extends TestCase
{
    protected string $projectDir;

    protected function setUp(): void
    {
        $this->projectDir = sys_get_temp_dir() . '/auth-client-install-' . bin2hex(random_bytes(6));
        mkdir($this->projectDir . '/config/packages', 0o775, true);
    }

    protected function tearDown(): void
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->projectDir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        );
        foreach ($iterator as $file) {
            \assert($file instanceof \SplFileInfo);
            $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }
        rmdir($this->projectDir);
    }

    protected function put(string $path, string $content): void
    {
        file_put_contents($this->projectDir . '/' . $path, $content);
    }

    protected function fixture(string $name): string
    {
        return (string) file_get_contents(__DIR__ . '/Fixtures/' . $name);
    }

    protected function read(string $path): string
    {
        return (string) file_get_contents($this->projectDir . '/' . $path);
    }

    /**
     * @return array<string, string> relative path => sha1 of every file in the project
     */
    protected function snapshot(): array
    {
        $files = [];
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->projectDir, \FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            \assert($file instanceof \SplFileInfo);
            $files[substr($file->getPathname(), \strlen($this->projectDir) + 1)] = (string) sha1_file($file->getPathname());
        }
        ksort($files);

        return $files;
    }
}
