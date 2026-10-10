<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Security\Stateless;

use Musikhood\AuthClient\Dto\UserData;
use Musikhood\AuthClient\Jwt\JwtClaims;
use Musikhood\AuthClient\Security\Stateless\StatelessPanelUser;
use Musikhood\AuthClient\Security\Stateless\StatelessPanelUserRepository;
use Musikhood\AuthClient\Security\UserMirrorSyncer;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

final class StatelessPanelUserRepositoryTest extends TestCase
{
    public function testFirstRequestBuildsTheUserFromJwtClaims(): void
    {
        $repository = new StatelessPanelUserRepository(new ArrayAdapter(), new NullLogger());
        $id = Uuid::uuid4();

        $user = (new UserMirrorSyncer($repository))->upsert($this->claims($id, ['EDIT']));

        self::assertInstanceOf(StatelessPanelUser::class, $user);
        self::assertSame('jan@example.com', $user->getUserIdentifier());
        self::assertSame(['ROLE_USER', 'ROLE_EDIT'], $user->getRoles());
    }

    public function testRolesFromMePropagateToTheNextRequestDespiteStaleJwt(): void
    {
        $cache = new ArrayAdapter();
        $id = Uuid::uuid4();

        // Request 1: JWT says EDIT, introspection (/me) says EDIT + PUBLISH.
        $repository = new StatelessPanelUserRepository($cache, new NullLogger());
        $syncer = new UserMirrorSyncer($repository);
        $authenticated = $syncer->upsert($this->claims($id, ['EDIT']));
        $syncer->syncFromMe($this->me($id, ['EDIT', 'PUBLISH']));
        self::assertSame(['ROLE_USER', 'ROLE_EDIT', 'ROLE_PUBLISH'], $authenticated->getRoles(), 'same object as the security token user');

        // Request 2 (validation cached, no /me call): the stale JWT must not win.
        $repository->reset();
        $next = (new UserMirrorSyncer($repository))->upsert($this->claims($id, ['EDIT']));
        self::assertSame(['ROLE_USER', 'ROLE_EDIT', 'ROLE_PUBLISH'], $next->getRoles());

        // Another process (fresh repository, shared cache.app) sees the same.
        $other = new StatelessPanelUserRepository($cache, new NullLogger());
        self::assertSame(['EDIT', 'PUBLISH'], $other->findById($id)?->getRolesForPanel());
    }

    public function testResetClearsTheIdentityMapButNotTheSnapshot(): void
    {
        $repository = new StatelessPanelUserRepository(new ArrayAdapter(), new NullLogger());
        $id = Uuid::uuid4();
        $user = $repository->createFromClaims($id, 'a@b.pl', null, []);
        $repository->save($user);

        self::assertSame($user, $repository->findByEmail('A@B.pl'));
        $repository->reset();
        self::assertNull($repository->findByEmail('a@b.pl'), 'no e-mail index across requests in stateless mode');
        self::assertNull($repository->findById($id), 'save() without flush() is not persisted');
    }

    public function testUnreadableSnapshotIsIgnored(): void
    {
        $cache = new ArrayAdapter();
        $id = Uuid::uuid4();
        $item = $cache->getItem('auth_client_user_' . $id->toString());
        $item->set(['id' => 'not-a-uuid']);
        $cache->save($item);

        self::assertNull((new StatelessPanelUserRepository($cache, new NullLogger()))->findById($id));
    }

    /**
     * @param list<string> $panelRoles
     */
    private function claims(UuidInterface $id, array $panelRoles): JwtClaims
    {
        return new JwtClaims(
            userId: $id,
            email: 'jan@example.com',
            displayName: 'Jan',
            panelId: null,
            panelName: null,
            panelRoles: $panelRoles,
            issuedAt: new \DateTimeImmutable(),
            expiresAt: new \DateTimeImmutable('+15 minutes'),
        );
    }

    /**
     * @param list<string> $panelRoles
     */
    private function me(UuidInterface $id, array $panelRoles): UserData
    {
        return new UserData(
            id: $id,
            email: 'jan@example.com',
            displayName: 'Jan',
            roles: [],
            panelId: null,
            panelName: null,
            panelRoles: $panelRoles,
            disabled: false,
        );
    }
}
