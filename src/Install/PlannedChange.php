<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Install;

/**
 * One step of `auth-client:install`. For Create/Modify `newContent` is the full
 * resulting file; for Manual `snippet` is what the user should paste.
 */
final readonly class PlannedChange
{
    public function __construct(
        public ChangeKind $kind,
        public string $path,
        public string $summary,
        public ?string $oldContent = null,
        public ?string $newContent = null,
        public ?string $snippet = null,
    ) {}

    public static function unchanged(string $path, string $summary): self
    {
        return new self(ChangeKind::Unchanged, $path, $summary);
    }

    public static function create(string $path, string $summary, string $content): self
    {
        return new self(ChangeKind::Create, $path, $summary, null, $content);
    }

    public static function modify(string $path, string $summary, string $old, string $new): self
    {
        return new self(ChangeKind::Modify, $path, $summary, $old, $new);
    }

    public static function manual(string $path, string $summary, string $snippet): self
    {
        return new self(ChangeKind::Manual, $path, $summary, null, null, $snippet);
    }

    public function writes(): bool
    {
        return ChangeKind::Create === $this->kind || ChangeKind::Modify === $this->kind;
    }
}
