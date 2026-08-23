<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts;

use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;

/**
 * A read-only reconnaissance unit producing a {@see ProbeResult}.
 *
 * Invariants (review-blocking):
 * - probes consume {@see NetTarget::$ips} only; re-resolving inside a probe is
 *   a TOCTOU/DNS-rebinding smell;
 * - the returned DTO must contain state only — no closures, no behavior, and
 *   its toArray()/fromArray() round-trip must be lossless (cache-purity rule).
 */
interface NettoolsProbeContract
{
    /** Card + log name ("whois", "dns"). */
    public function name(): string;

    /** Success-cache TTL in seconds; 0 = never cache (measurements). */
    public function ttlSeconds(): int;

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult;
}
