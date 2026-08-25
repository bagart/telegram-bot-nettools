<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts;

/**
 * Outbound HTTP seam for sources (RDAP, CT logs, geo APIs). Narrow on
 * purpose: sources never see the platform transport — tests fake this.
 *
 * Implementations follow redirects internally (RDAP bootstrap/rdap.org
 * redirect to registry servers) and return null on any failure — network
 * problems are a degradation signal, not an exception path.
 */
interface SourceHttpContract
{
    /**
     * GET $url expecting a JSON document.
     *
     * @param  int  $timeoutSeconds  hard wall-clock cap for the whole call,
     *                               including ≤2 redirect hops
     * @return array<string, mixed>|list<mixed>|null decoded JSON object or
     *                                   top-level list (CT sources answer
     *                                   with bare arrays); null = timeout,
     *                                   transport error or non-2xx
     */
    public function getJson(string $url, int $timeoutSeconds): ?array;
}
