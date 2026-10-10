<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Install;

use Musikhood\AuthClient\Install\ChangeKind;
use Musikhood\AuthClient\Install\SecurityConfigurator;
use Musikhood\AuthClient\Routing\PublicRoutes;
use Musikhood\AuthClient\Security\JwtCookieAuthenticator;
use Symfony\Component\Yaml\Yaml;

final class SecurityConfiguratorTest extends InstallTestCase
{
    public function testMissingFileGetsTheFullTemplate(): void
    {
        $change = (new SecurityConfigurator())->plan($this->projectDir);

        self::assertSame(ChangeKind::Create, $change->kind);
        self::assertSame(SecurityConfigurator::template(), $change->newContent);
    }

    public function testTemplateIsValidYamlAndCoversEveryBundleRoute(): void
    {
        $parsed = Yaml::parse(SecurityConfigurator::template());
        self::assertIsArray($parsed);
        self::assertSame(PublicRoutes::pattern(), $parsed['security']['firewalls']['login']['pattern']);
        self::assertFalse($parsed['security']['firewalls']['login']['security']);
        self::assertContains(JwtCookieAuthenticator::class, $parsed['security']['firewalls']['api']['custom_authenticators']);

        // Fed back to the planner, the generated file is recognized as complete.
        $this->put(SecurityConfigurator::PATH, SecurityConfigurator::template());
        self::assertSame(ChangeKind::Unchanged, (new SecurityConfigurator())->plan($this->projectDir)->kind);
    }

    public function testStockSymfonyFileIsReplacedKeepingWhenSections(): void
    {
        $this->put(SecurityConfigurator::PATH, $this->fixture('security.stock.yaml'));

        $change = (new SecurityConfigurator())->plan($this->projectDir);

        self::assertSame(ChangeKind::Modify, $change->kind);
        $parsed = Yaml::parse((string) $change->newContent);
        self::assertIsArray($parsed);
        self::assertArrayHasKey('login', $parsed['security']['firewalls']);
        self::assertSame(4, $parsed['when@test']['security']['password_hashers']['Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface']['cost']);
    }

    public function testPim07ConfigurationNeedsNoChange(): void
    {
        // PIM 0.7: own `login` firewall + webhook via PUBLIC_ACCESS in the api firewall.
        $this->put(SecurityConfigurator::PATH, $this->fixture('security.pim07.yaml'));

        $change = (new SecurityConfigurator())->plan($this->projectDir);

        self::assertSame(ChangeKind::Unchanged, $change->kind, $change->summary);
    }

    public function testCustomFirewallsAreNeverRewritten(): void
    {
        $this->put(SecurityConfigurator::PATH, $this->fixture('security.custom.yaml'));

        $change = (new SecurityConfigurator())->plan($this->projectDir);

        self::assertSame(ChangeKind::Manual, $change->kind);
        self::assertNull($change->newContent);
        self::assertStringContainsString('/api/login/mfa', $change->summary);
        self::assertStringContainsString(PublicRoutes::pattern(), (string) $change->snippet);
    }

    public function testUnevaluableMatchersFallBackToManual(): void
    {
        $this->put(SecurityConfigurator::PATH, $this->fixture('security.host.yaml'));

        self::assertSame(ChangeKind::Manual, (new SecurityConfigurator())->plan($this->projectDir)->kind);
    }

    public function testBrokenYamlFallsBackToManual(): void
    {
        $this->put(SecurityConfigurator::PATH, "security:\n  firewalls: [unclosed\n");

        self::assertSame(ChangeKind::Manual, (new SecurityConfigurator())->plan($this->projectDir)->kind);
    }
}
