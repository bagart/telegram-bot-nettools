<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts;

use BAGArt\TelegramBotNettools\Sources\FetchOutcome;

/**
 * Raw HTTP seam for the HttpProbe (RFC §7.13). Deliberately returns a
 * state-only outcome (never throws, never null): transport failures are
 * values (`status 0` + `error`), so probes can distinguish refused vs
 * timeout vs TLS without exception plumbing.
 */
interface FetcherContract
{
    /**
     * Single request; no internal redirect following (the probe renders each
     * hop). Extra curl options (e.g. CURLOPT_RESOLVE pinning) pass through.
     *
     * @param  array<string, string>  $headers
     * @param  array<int, mixed>  $curlOptions
     */
    public function fetch(string $url, string $method, int $timeoutSeconds, array $headers = [], array $curlOptions = []): FetchOutcome;
}
