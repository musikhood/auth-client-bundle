<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Security\Stateless;

use Musikhood\AuthClient\Contract\PanelUserInterface;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;

/**
 * Built-in user of the stateless (default) mode: no entity, no table. Built
 * from JWT claims and refreshed from the auth server's /me (introspection)
 * by {@see \Musikhood\AuthClient\Security\UserMirrorSyncer}.
 *
 * Roles follow the same convention as the reference entity
 * (docs/example-entity.php): ROLE_USER + `ROLE_` + each panel role.
 */
final class StatelessPanelUser implements PanelUserInterface
{
    /**
     * @param list<string> $rolesForPanel role names without the ROLE_ prefix
     */
    public function __construct(
        private readonly UuidInterface $id,
        private string $email,
        private ?string $displayName,
        private array $rolesForPanel,
        private bool $disabled = false,
    ) {}

    /**
     * @param array{id: string, email: string, displayName: ?string, rolesForPanel: list<string>, disabled: bool} $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            Uuid::fromString($data['id']),
            $data['email'],
            $data['displayName'],
            $data['rolesForPanel'],
            $data['disabled'],
        );
    }

    /**
     * @return array{id: string, email: string, displayName: ?string, rolesForPanel: list<string>, disabled: bool}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id->toString(),
            'email' => $this->email,
            'displayName' => $this->displayName,
            'rolesForPanel' => $this->rolesForPanel,
            'disabled' => $this->disabled,
        ];
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

    /**
     * @param list<string> $rolesForPanel
     */
    public function syncFromClaims(string $email, ?string $displayName, array $rolesForPanel): void
    {
        $this->email = $email;
        $this->displayName = $displayName;
        $this->rolesForPanel = array_values($rolesForPanel);
    }

    public function markDisabled(bool $disabled): void
    {
        $this->disabled = $disabled;
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
        // E-mail is always present in the auth server's JWT; the id is a defensive fallback.
        $identifier = '' !== $this->email ? $this->email : $this->id->toString();
        \assert('' !== $identifier);

        return $identifier;
    }

    public function eraseCredentials(): void
    {
    }
}
