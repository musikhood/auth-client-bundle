<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Install;

use Musikhood\AuthClient\Install\ChangeKind;
use Musikhood\AuthClient\Install\CorsConfigurator;
use Symfony\Component\Yaml\Yaml;

final class CorsConfiguratorTest extends InstallTestCase
{
    public function testWithoutNelmioPrintsInstructions(): void
    {
        $change = (new CorsConfigurator())->plan($this->projectDir, nelmioInstalled: false);

        self::assertSame(ChangeKind::Manual, $change->kind);
        self::assertStringContainsString('nelmio/cors-bundle', $change->summary);
    }

    public function testMissingFileIsCreated(): void
    {
        $change = (new CorsConfigurator())->plan($this->projectDir, nelmioInstalled: true);

        self::assertSame(ChangeKind::Create, $change->kind);
        self::assertTrue(CorsConfigurator::satisfies((string) $change->newContent));
    }

    public function testNelmioRecipeFileIsEditedInPlace(): void
    {
        $this->put(CorsConfigurator::PATH, $this->fixture('nelmio_cors.stock.yaml'));

        $change = (new CorsConfigurator())->plan($this->projectDir, nelmioInstalled: true);

        self::assertSame(ChangeKind::Modify, $change->kind);
        $parsed = Yaml::parse((string) $change->newContent);
        self::assertIsArray($parsed);
        $defaults = $parsed['nelmio_cors']['defaults'];
        self::assertTrue($defaults['allow_credentials']);
        self::assertSame(['Content-Type', 'Authorization', 'X-Device-Fp'], $defaults['allow_headers']);
        self::assertSame(['Link', 'Retry-After'], $defaults['expose_headers']);
        // Untouched keys stay as they were.
        self::assertSame(['GET', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'], $defaults['allow_methods']);
        self::assertSame(['^/' => null], $parsed['nelmio_cors']['paths']);
    }

    public function testPim07FileNeedsNoChange(): void
    {
        $this->put(CorsConfigurator::PATH, $this->fixture('nelmio_cors.pim07.yaml'));

        self::assertSame(ChangeKind::Unchanged, (new CorsConfigurator())->plan($this->projectDir, nelmioInstalled: true)->kind);
    }

    public function testBlockListsAreNotEditedAutomatically(): void
    {
        $this->put(CorsConfigurator::PATH, $this->fixture('nelmio_cors.block.yaml'));

        $change = (new CorsConfigurator())->plan($this->projectDir, nelmioInstalled: true);

        self::assertSame(ChangeKind::Manual, $change->kind);
        self::assertSame($this->fixture('nelmio_cors.block.yaml'), $this->read(CorsConfigurator::PATH));
    }
}
