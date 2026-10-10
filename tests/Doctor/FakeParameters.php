<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Tests\Doctor;

use Symfony\Component\DependencyInjection\Exception\EnvNotFoundException;
use Symfony\Component\DependencyInjection\Exception\ParameterNotFoundException;
use Symfony\Component\DependencyInjection\ParameterBag\ContainerBagInterface;

/**
 * Parameters as the compiled container resolves them; a value of
 * self::MISSING_ENV behaves like an undefined %env()%.
 */
final class FakeParameters implements ContainerBagInterface
{
    public const MISSING_ENV = "\0missing-env";

    /**
     * @param array<string, mixed> $values
     */
    public function __construct(private array $values) {}

    public function get(string $id): mixed
    {
        if (!\array_key_exists($id, $this->values)) {
            throw new ParameterNotFoundException($id);
        }
        if (self::MISSING_ENV === $this->values[$id]) {
            throw new EnvNotFoundException(sprintf('Environment variable not found for "%s".', $id));
        }

        return $this->values[$id];
    }

    public function has(string $id): bool
    {
        return \array_key_exists($id, $this->values);
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->values;
    }

    /**
     * @return mixed
     */
    public function resolveValue(mixed $value): mixed
    {
        return $value;
    }

    public function escapeValue(mixed $value): mixed
    {
        return $value;
    }

    public function unescapeValue(mixed $value): mixed
    {
        return $value;
    }
}
