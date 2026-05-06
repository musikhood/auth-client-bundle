<?php

declare(strict_types=1);

// PRZYKŁAD — skopiuj do swojego src/Repository/UserRepository.php i dostosuj
// namespace. Atrybut #[AsAlias] sprawia, że Symfony sam podepnie to repo
// pod kontrakt PanelUserRepositoryInterface — nic nie musisz wpisywać do
// services.yaml. Wymaga Symfony 6.1+.

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Musikhood\AuthClient\Contract\PanelUserInterface;
use Musikhood\AuthClient\Contract\PanelUserRepositoryInterface;
use Ramsey\Uuid\UuidInterface;
use Symfony\Component\DependencyInjection\Attribute\AsAlias;

/**
 * @extends ServiceEntityRepository<User>
 */
#[AsAlias(id: PanelUserRepositoryInterface::class)]
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
