<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Install;

use Musikhood\AuthClient\Install\ChangeKind;
use Musikhood\AuthClient\Install\Installer;
use Musikhood\AuthClient\Install\LineDiff;
use Musikhood\AuthClient\Install\PlannedChange;

final class InstallerTest extends InstallTestCase
{
    public function testPlanningNeverWrites(): void
    {
        $this->put('config/packages/security.yaml', $this->fixture('security.stock.yaml'));
        $this->put('config/packages/nelmio_cors.yaml', $this->fixture('nelmio_cors.stock.yaml'));
        $this->put('.env', "APP_ENV=dev\n");
        $before = $this->snapshot();

        $changes = (new Installer())->plan($this->projectDir, true, 70400);

        self::assertNotEmpty(array_filter($changes, static fn (PlannedChange $c): bool => $c->writes()));
        self::assertSame($before, $this->snapshot(), 'plan() (dry-run) must not touch any file');
    }

    public function testApplyThenSecondRunChangesNothing(): void
    {
        $this->put('config/packages/security.yaml', $this->fixture('security.stock.yaml'));
        $this->put('config/packages/nelmio_cors.yaml', $this->fixture('nelmio_cors.stock.yaml'));
        $this->put('.env', "APP_ENV=dev\n");
        $installer = new Installer();

        $installer->apply($this->projectDir, $installer->plan($this->projectDir, true, 70400));
        $second = $installer->plan($this->projectDir, true, 70400);

        foreach ($second as $change) {
            self::assertSame(ChangeKind::Unchanged, $change->kind, $change->path . ': ' . $change->summary);
        }
    }

    public function testFreshProjectGetsEverythingIncludingCorsOriginEnv(): void
    {
        $installer = new Installer();
        $installer->apply($this->projectDir, $installer->plan($this->projectDir, true, 70400));

        $env = $this->read('.env');
        self::assertStringContainsString('CORS_ALLOW_ORIGIN=', $env);
        self::assertStringContainsString('SYMFONY_TRUSTED_PROXIES=private_ranges', $env);
        self::assertFileExists($this->projectDir . '/config/packages/security.yaml');
        self::assertFileExists($this->projectDir . '/config/packages/nelmio_cors.yaml');
    }

    public function testPim07ProjectIsAlreadyComplete(): void
    {
        $this->put('config/packages/security.yaml', $this->fixture('security.legacy07.yaml'));
        $this->put('config/packages/nelmio_cors.yaml', $this->fixture('nelmio_cors.legacy07.yaml'));
        mkdir($this->projectDir . '/config/routes');
        $this->put('config/routes/auth_client.yaml', "auth_client:\n    resource: '@AuthClientBundle/Resources/config/routes.yaml'\n");
        $this->put('.env', "SYMFONY_TRUSTED_PROXIES=private_ranges\n");
        // Existing app: AUTH_* come from .env.local / k8s secrets, not from .env.
        $definedEnv = array_keys(Installer::PANEL_ENV);

        $changes = (new Installer())->plan($this->projectDir, true, 70400, $definedEnv);

        self::assertSame([], array_filter($changes, static fn (PlannedChange $c): bool => ChangeKind::Unchanged !== $c->kind));
    }

    public function testPanelEnvIsAddedToDotEnvOnlyWhenUndefined(): void
    {
        $this->put('.env', "APP_ENV=dev\nAUTH_CLIENT_ID=from-dotenv\n");
        $installer = new Installer();

        $installer->apply($this->projectDir, $installer->plan($this->projectDir, false, 70400, ['AUTH_CLIENT_SECRET']));

        $env = $this->read('.env');
        self::assertStringContainsString("AUTH_BASE_URL=\nAUTH_PANEL_ID=\n", $env, 'empty like the panel values; one group, no blank lines between keys');
        self::assertSame(1, substr_count($env, 'AUTH_CLIENT_ID='), 'existing key kept, not duplicated');
        self::assertStringNotContainsString('AUTH_CLIENT_SECRET', $env, 'defined in the environment (e.g. .env.local) → not added');
        self::assertStringContainsString('secret_to_env', $env);
    }

    public function testRoutesAreImportedOnce(): void
    {
        $installer = new Installer();
        $installer->apply($this->projectDir, $installer->plan($this->projectDir, false, 70400));

        self::assertStringContainsString('@AuthClientBundle/Resources/config/routes.yaml', $this->read('config/routes/auth_client.yaml'));
        $again = $installer->plan($this->projectDir, false, 70400);
        self::assertSame([], array_filter($again, static fn (PlannedChange $c): bool => $c->writes()));
    }

    public function testLineDiffShowsOnlyChangedRegion(): void
    {
        $lines = LineDiff::render("a\nb\nc\nd\ne\nf\ng\n", "a\nb\nc\nX\ne\nf\ng\n", 1);

        self::assertSame(['  c', '- d', '+ X', '  e'], $lines);
    }
}
