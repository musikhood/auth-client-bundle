<?php

declare(strict_types=1);

// EXAMPLE — copy this into your application's src/Entity/User.php and adapt
// the namespace + repositoryClass. The bundle never touches this file; it
// only knows about Musikhood\AuthClient\Contract\PanelUserInterface.

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;
use Musikhood\AuthClient\Contract\PanelUserInterface;
use Ramsey\Uuid\UuidInterface;

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: 'users')]
#[ORM\UniqueConstraint(name: 'uniq_users_email', columns: ['email'])]
#[ORM\Index(name: 'idx_users_email', columns: ['email'])]
class User implements PanelUserInterface
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private UuidInterface $id;

    #[ORM\Column(type: 'string', length: 180, unique: true)]
    private string $email;

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    private ?string $displayName = null;

    /** @var list<string> */
    #[ORM\Column(type: 'json')]
    private array $rolesForPanel = [];

    #[ORM\Column(type: 'boolean', options: ['default' => false])]
    private bool $disabled = false;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $lastSyncedAt;

    private function __construct() {}

    /**
     * @param list<string> $rolesForPanel role names without the ROLE_ prefix
     */
    public static function create(
        UuidInterface $id,
        string $email,
        ?string $displayName,
        array $rolesForPanel,
    ): self {
        $user = new self();
        $user->id = $id;
        $user->email = $email;
        $user->displayName = $displayName;
        $user->rolesForPanel = array_values($rolesForPanel);
        $user->disabled = false;
        $user->lastSyncedAt = new \DateTimeImmutable();

        return $user;
    }

    /**
     * @param list<string> $rolesForPanel
     */
    public function syncFromClaims(string $email, ?string $displayName, array $rolesForPanel): void
    {
        $this->email = $email;
        $this->displayName = $displayName;
        $this->rolesForPanel = array_values($rolesForPanel);
        $this->lastSyncedAt = new \DateTimeImmutable();
    }

    public function markDisabled(bool $disabled): void
    {
        $this->disabled = $disabled;
    }

    public function getId(): UuidInterface
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
        return $this->rolesForPanel;
    }

    public function isDisabled(): bool
    {
        return $this->disabled;
    }

    /** @return list<string> */
    public function getRoles(): array
    {
        $roles = ['ROLE_USER'];
        foreach ($this->rolesForPanel as $role) {
            $roles[] = 'ROLE_' . $role;
        }

        return array_values(array_unique($roles));
    }

    public function getUserIdentifier(): string
    {
        return $this->email;
    }

    public function eraseCredentials(): void
    {
    }
}
