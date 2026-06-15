<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\EventListener;

use Musikhood\AuthClient\Contract\PanelUserInterface;
use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Musikhood\AuthClient\EventListener\AuthValidationListener;
use Musikhood\AuthClient\Http\AuthBackendClient;
use Musikhood\AuthClient\Jwt\JwtClaims;
use Musikhood\AuthClient\Security\JwtCookieAuthenticator;
use Musikhood\AuthClient\Security\UserMirrorSyncer;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Make-or-break Fazy 2: introspekcja per-request mapuje 403 (brak dostępu do
 * panelu) na AccessDeniedHttpException (→ 403 do frontu, bez czyszczenia/refresh),
 * 401 (sesja martwa) na UnauthorizedHttpException, a 5xx/transport fail-OPEN
 * (NIE wylogowuje przy awarii mastera).
 */
final class AuthValidationListenerTest extends TestCase
{
    public function testForbiddenIntrospectionThrowsAccessDenied403(): void
    {
        $event = $this->dispatch(new MockResponse(
            (string) json_encode(['error' => 'Brak dostępu do tego panelu.']),
            ['http_code' => 403],
        ));

        $this->expectException(AccessDeniedHttpException::class);
        ($event)();
    }

    public function testUnauthorizedIntrospectionThrowsUnauthorized401(): void
    {
        $event = $this->dispatch(new MockResponse('', ['http_code' => 401]));

        $this->expectException(UnauthorizedHttpException::class);
        ($event)();
    }

    public function testServerErrorFailsOpen(): void
    {
        // 5xx = awaria mastera → fail OPEN: brak wyjątku, request przechodzi.
        $run = $this->dispatch(new MockResponse('', ['http_code' => 503]));
        ($run)();
        self::assertTrue(true);
    }

    public function testTransportErrorFailsOpen(): void
    {
        // Timeout/transport → fail OPEN.
        $run = $this->dispatch(new MockResponse('', ['error' => 'Connection timed out']));
        ($run)();
        self::assertTrue(true);
    }

    public function testSuccessfulIntrospectionDoesNotThrowAndSyncs(): void
    {
        $userId = Uuid::uuid4();
        $payload = [
            'id' => $userId->toString(),
            'email' => 'jan@example.com',
            'displayName' => 'Jan',
            'roles' => ['ROLE_USER'],
            'panelId' => Uuid::uuid4()->toString(),
            'panelName' => 'pim',
            'panelRoles' => ['EDIT'],
            'disabled' => false,
        ];

        $run = $this->dispatch(
            new MockResponse((string) json_encode($payload), ['http_code' => 200]),
            $userId,
        );
        ($run)();
        self::assertTrue(true);
    }

    /**
     * Buduje listener z realnym AuthBackendClient (MockHttpClient) i zwraca
     * callable odpalający __invoke na świeżym ControllerEvent. Zwracamy callable
     * (nie wywołujemy od razu), żeby expectException objął tylko wywołanie.
     */
    private function dispatch(MockResponse $introspectResponse, ?UuidInterface $userId = null): callable
    {
        $userId ??= Uuid::uuid4();

        $http = new MockHttpClient([$introspectResponse]);
        $backendClient = new AuthBackendClient(
            $http,
            new NullLogger(),
            'https://auth.example',
            'cid',
            'csecret',
            5.0,
            10.0,
        );

        $userRepo = $this->createMock(PanelUserRepositoryInterface::class);
        $userRepo->method('findById')->willReturn($this->createMock(PanelUserInterface::class));
        $syncer = new UserMirrorSyncer($userRepo);

        $listener = new AuthValidationListener(
            $backendClient,
            $syncer,
            new ArrayAdapter(), // pusty cache → zawsze odpala introspekcję
            new NullLogger(),
            30,   // validationCacheTtl
            5,    // circuitBreakerFailureThreshold
            60,   // circuitBreakerOpenSeconds
        );

        $claims = new JwtClaims(
            userId: $userId,
            email: 'jan@example.com',
            displayName: 'Jan',
            panelId: null,
            panelName: null,
            panelRoles: [],
            issuedAt: new \DateTimeImmutable(),
            expiresAt: new \DateTimeImmutable('+15 minutes'),
            tokenVersion: 1,
        );

        $request = new Request();
        $request->attributes->set(JwtCookieAuthenticator::ATTR_ACCESS_TOKEN, 'jwt-access');
        $request->attributes->set(JwtCookieAuthenticator::ATTR_CLAIMS, $claims);

        $event = new ControllerEvent(
            $this->createMock(HttpKernelInterface::class),
            static fn () => null,
            $request,
            HttpKernelInterface::MAIN_REQUEST,
        );

        return static fn () => $listener($event);
    }
}
