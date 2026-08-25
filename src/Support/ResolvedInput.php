<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

/**
 * Intermediate normalization output: parsed host before resolution/guard.
 */
final readonly class ResolvedInput
{
    public function __construct(
        public string $rawInput,
        /** punycode host or IP literal (lowercase, no trailing dot) */
        public string $host,
        public bool $isIp,
        /** only 80/443 survive normalization (URL inputs) */
        public ?int $port,
    ) {
    }
}
