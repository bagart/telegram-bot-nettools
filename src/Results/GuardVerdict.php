<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Results;

/**
 * Verdict attached to a normalized target before any egress.
 * Closed set: {@see self::allow()} / {@see self::block()}.
 */
final readonly class GuardVerdict
{
    private function __construct(
        public bool $allowed,
        public ?string $reason,
        public ?string $label,
    ) {
    }

    /** @param  string|null  $label  informational label (e.g. "TEST-NET-1") */
    public static function allow(?string $label = null): self
    {
        return new self(true, null, $label);
    }

    public static function block(string $reason): self
    {
        return new self(false, $reason, null);
    }

    public function isBlocked(): bool
    {
        return ! $this->allowed;
    }
}
