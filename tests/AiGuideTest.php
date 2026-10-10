<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests;

use Musikhood\AuthClient\AiGuide;
use PHPUnit\Framework\TestCase;

final class AiGuideTest extends TestCase
{
    public function testGuideShipsWithTheBundle(): void
    {
        self::assertFileExists(AiGuide::absolutePath());
    }

    public function testPathIsRelativeInsideTheProject(): void
    {
        // As in vendor/musikhood/auth-client-bundle: the project dir is an ancestor of the bundle.
        $bundleRoot = \dirname(AiGuide::absolutePath());
        $expected = basename($bundleRoot) . '/' . AiGuide::FILE;

        self::assertSame($expected, AiGuide::displayPath(\dirname($bundleRoot)));
        self::assertSame($expected, AiGuide::displayPath(\dirname($bundleRoot) . '/'));
    }

    public function testPathIsAbsoluteOutsideTheProject(): void
    {
        self::assertSame(AiGuide::absolutePath(), AiGuide::displayPath('/nonexistent/project'));
    }
}
