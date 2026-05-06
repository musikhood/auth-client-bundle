<?php

declare(strict_types=1);

// EXAMPLE — copy this into your application's src/Repository/UserRepository.php
// and adapt the namespace. The bundle reaches the repository only through
// PanelUserRepositoryInterface, so register an alias in services.yaml:
//
// services:
//     Musikhood\AuthClient\Contract\PanelUserRepositoryInterface:
//         alias: App\Repository\UserRepository

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Musikhood\AuthClient\Contract\PanelUserInterface;
use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Ramsey\Uuid\UuidInterface;

/**
 * @extends ServiceEntityRepository<User>
 */
class UserRepository extends ServiceEntityRepository implements PanelUserRepositoryInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function findById(UuidInterface $id): ?PanelUserInterface
    {
        return $this->find($id);
    }

    public function findByEmail(string $email): ?PanelUserInterface
    {
        return $this->findOneBy(['email' => $email]);
    }

    public function save(PanelUserInterface $user): void
    {
        $this->getEntityManager()->persist($user);
    }

    public function flush(): void
    {
        $this->getEntityManager()->flush();
    }

    public function createFromClaims(
        UuidInterface $id,
        string $email,
        ?string $displayName,
        array $rolesForPanel,
    ): PanelUserInterface {
        return User::create($id, $email, $displayName, $rolesForPanel);
    }
}
