<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Security;

use Musikhood\AuthClient\Contract\PanelUserInterface;
use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Musikhood\AuthClient\Http\AuthBackendClient;
use Musikhood\AuthClient\Security\ApiTokenAuthenticator;
use Musikhood\AuthClient\Security\UserMirrorSyncer;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Ramsey\Uuid\Uuid;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

final class ApiTokenAuthenticatorTest extends TestCase
{
    private const HEADER = 'X-Api-Token';
    private const PANEL_ID = 'b1d1c0de-0000-4000-8000-000000000001';

    public function testSupportsOnlyWithHeader(): void
    {
        $auth = $this->authenticator(new MockHttpClient([]));

        self::assertFalse($auth->supports(new Request()));
        self::assertTrue($auth->supports($this->requestWithToken('mhpat_x')));
    }

    public function testInvalidTokenThrows(): void
    {
        $auth = $this->authenticator(new MockHttpClient([new MockResponse('', ['http_code' => 401])]));

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $auth->authenticate($this->requestWithToken('mhpat_bad'));
    }

    public function testBackendUnavailableFailsClosed(): void
    {
        $auth = $this->authenticator(new MockHttpClient([new MockResponse('', ['http_code' => 503])]));

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $auth->authenticate($this->requestWithToken('mhpat_x'));
    }

    public function testForeignPanelThrows(): void
    {
        $auth = $this->authenticator(new MockHttpClient([
            new MockResponse((string) json_encode($this->payload(panelId: Uuid::uuid4()->toString())), ['http_code' => 200]),
        ]));

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $auth->authenticate($this->requestWithToken('mhpat_x'));
    }

    public function testDisabledThrows(): void
    {
        $auth = $this->authenticator(new MockHttpClient([
            new MockResponse((string) json_encode($this->payload(disabled: true)), ['http_code' => 200]),
        ]));

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $auth->authenticate($this->requestWithToken('mhpat_x'));
    }

    public function testHappyPathSyncsAndBuildsPassport(): void
    {
        $http = new MockHttpClient([
            new MockResponse((string) json_encode($this->payload()), ['http_code' => 200]),
        ]);
        $auth = $this->authenticator($http);

        $passport = $auth->authenticate($this->requestWithToken('mhpat_good'));

        self::assertSame('u@example.com', $passport->getUser()->getUserIdentifier());
    }

    /**
     * @return array<string, mixed>
     */
    private function payload(?string $panelId = self::PANEL_ID, bool $disabled = false): array
    {
        return [
            'id' => Uuid::uuid4()->toString(),
            'email' => 'u@example.com',
            'displayName' => 'Jan',
            'roles' => ['ROLE_ADMIN'],
            'panelId' => $panelId,
            'panelName' => 'editor-prod',
            'panelRoles' => ['PUBLISH'],
            'disabled' => $disabled,
        ];
    }

    private function authenticator(MockHttpClient $http): ApiTokenAuthenticator
    {
        $client = new AuthBackendClient($http, new NullLogger(), 'https://auth.example', 'cid', 'csecret', 5.0, 10.0);
        $syncer = new UserMirrorSyncer($this->repository());

        return new ApiTokenAuthenticator($client, $syncer, new NullLogger(), self::HEADER, self::PANEL_ID);
    }

    private function repository(): PanelUserRepositoryInterface
    {
        return new class implements PanelUserRepositoryInterface {
            private ?PanelUserInterface $user = null;

            public function findById(\Ramsey\Uuid\UuidInterface $id): ?PanelUserInterface
            {
                return $this->user;
            }

            public function findByEmail(string $email): ?PanelUserInterface
            {
                return null;
            }

            public function save(PanelUserInterface $user): void
            {
                $this->user = $user;
            }

            public function flush(): void
            {
            }

            public function createFromClaims(\Ramsey\Uuid\UuidInterface $id, string $email, ?string $displayName, array $rolesForPanel): PanelUserInterface
            {
                return $this->user = new class($id, $email, $displayName, $rolesForPanel) implements PanelUserInterface {
                    /** @param list<string> $roles */
                    public function __construct(
                        private \Ramsey\Uuid\UuidInterface $id,
                        private string $email,
                        private ?string $displayName,
                        private array $roles,
                        private bool $disabled = false,
                    ) {
                    }

                    public function getId(): \Ramsey\Uuid\UuidInterface
                    {
                        return $this->id;
                    }

                    public function getEmail(): string
                    {
                        return $this->email;
                    }

                    public function getDisplayName(): ?string
                    {
                        return $this->displayName;
                    }

                    /** @return list<string> */
                    public function getRolesForPanel(): array
                    {
                        return $this->roles;
                    }

                    public function isDisabled(): bool
                    {
                        return $this->disabled;
                    }

                    public function syncFromClaims(string $email, ?string $displayName, array $rolesForPanel): void
                    {
                        $this->email = $email;
                        $this->displayName = $displayName;
                        $this->roles = $rolesForPanel;
                    }

                    public function markDisabled(bool $disabled): void
                    {
                        $this->disabled = $disabled;
                    }

                    /** @return list<string> */
                    public function getRoles(): array
                    {
                        return array_map(static fn (string $r): string => 'ROLE_' . $r, $this->roles);
                    }

                    public function eraseCredentials(): void
                    {
                    }

                    public function getUserIdentifier(): string
                    {
                        return '' !== $this->email ? $this->email : 'anonymous';
                    }
                };
            }
        };
    }

    private function requestWithToken(string $token): Request
    {
        $request = new Request();
        $request->headers->set(self::HEADER, $token);

        return $request;
    }
}
