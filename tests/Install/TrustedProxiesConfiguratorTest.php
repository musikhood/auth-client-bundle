<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Install;

use Musikhood\AuthClient\Install\ChangeKind;
use Musikhood\AuthClient\Install\TrustedProxiesConfigurator;

final class TrustedProxiesConfiguratorTest extends InstallTestCase
{
    public function testSymfony72AndNewerOnlyNeedsTheEnv(): void
    {
        $this->put('.env', "APP_ENV=dev\n");

        [$framework, $env] = (new TrustedProxiesConfigurator())->plan($this->projectDir, 70400);

        self::assertSame(ChangeKind::Unchanged, $framework->kind);
        self::assertSame(ChangeKind::Modify, $env->kind);
        self::assertStringEndsWith("SYMFONY_TRUSTED_PROXIES=private_ranges\n", (string) $env->newContent);
        self::assertStringStartsWith("APP_ENV=dev\n", (string) $env->newContent);
    }

    public function testExistingEnvKeyIsKept(): void
    {
        $this->put('.env', "SYMFONY_TRUSTED_PROXIES=10.0.0.0/8\n");

        [, $env] = (new TrustedProxiesConfigurator())->plan($this->projectDir, 70400);

        self::assertSame(ChangeKind::Unchanged, $env->kind);
    }

    public function testOlderSymfonyGetsFrameworkLine(): void
    {
        $this->put('config/packages/framework.yaml', "framework:\n    secret: '%env(APP_SECRET)%'\n");

        [$framework] = (new TrustedProxiesConfigurator())->plan($this->projectDir, 60400);

        self::assertSame(ChangeKind::Modify, $framework->kind);
        self::assertStringContainsString(TrustedProxiesConfigurator::FRAMEWORK_LINE, (string) $framework->newContent);
        self::assertStringContainsString("secret: '%env(APP_SECRET)%'", (string) $framework->newContent);
    }

    public function testExplicitTrustedProxiesAreRespected(): void
    {
        $this->put('config/packages/framework.yaml', "framework:\n    trusted_proxies: '127.0.0.1'\n");

        $changes = (new TrustedProxiesConfigurator())->plan($this->projectDir, 70400);

        self::assertCount(1, $changes);
        self::assertSame(ChangeKind::Unchanged, $changes[0]->kind);
    }
}
