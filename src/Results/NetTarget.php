<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Results;

/**
 * Normalized probe target. Produced once by the guard pipeline
 * (normalize → resolve once → SSRF verdict) and reused by every probe.
 */
final readonly class NetTarget
{
    /**
     * @param  list<string>  $ips  pre-resolved by the guard pipeline — probes
     *                             MUST reuse these (single-resolution invariant)
     */
    public function __construct(
        public string $rawInput,
        public string $host,
        public array $ips,
        public bool $isDomain,
        public bool $isIp,
        public GuardVerdict $verdict,
    ) {
    }
}
