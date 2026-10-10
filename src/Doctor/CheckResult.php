<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Doctor;

/**
 * One line of `auth-client:doctor`: what was checked, the outcome and — when
 * not OK — what to do. Never carries secret values.
 */
final readonly class CheckResult
{
    public function __construct(
        public CheckStatus $status,
        public string $label,
        public ?string $detail = null,
        public ?string $hint = null,
    ) {}

    public static function ok(string $label, ?string $detail = null): self
    {
        return new self(CheckStatus::Ok, $label, $detail);
    }

    public static function warning(string $label, string $detail, ?string $hint = null): self
    {
        return new self(CheckStatus::Warning, $label, $detail, $hint);
    }

    public static function failure(string $label, string $detail, ?string $hint = null): self
    {
        return new self(CheckStatus::Failure, $label, $detail, $hint);
    }

    public static function skipped(string $label, string $detail, ?string $hint = null): self
    {
        return new self(CheckStatus::Skipped, $label, $detail, $hint);
    }
}
