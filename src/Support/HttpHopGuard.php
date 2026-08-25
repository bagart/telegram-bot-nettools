<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBotNettools\Contracts\DnsResolverContract;

/**
 * Per-hop SSRF re-check for manually followed redirects (todo P1-1): every
 * redirect target is resolved ONCE and classified through the same matrix
 * verdict as the original target before any connection is made. Cross-scheme
 * downgrades (https→http) are denied; the approved IP is returned for
 * CURLOPT_RESOLVE pinning so the connection cannot drift to another address.
 */
final class HttpHopGuard
{
    public function __construct(
        private readonly DnsResolverContract $dnsLookup = new DnsLookup(),
        private readonly SsrfGuard $guard = new SsrfGuard(),
    ) {
    }

    /**
     * @param  string|null  $currentScheme  scheme of the URL that issued the redirect
     * @return array{ip: ?string, reason: ?string} ip = pin target when reason is null
     */
    public function approve(string $nextUrl, ?string $currentScheme): array
    {
        $parts = parse_url($nextUrl);
        $scheme = strtolower(is_string($parts['scheme'] ?? null) ? $parts['scheme'] : '');
        $host = $parts['host'] ?? null;

        if (! in_array($scheme, ['http', 'https'], true) || ! is_string($host) || $host === '') {
            return ['ip' => null, 'reason' => 'bad_redirect_target'];
        }

        if ($currentScheme === 'https' && $scheme === 'http') {
            return ['ip' => null, 'reason' => 'downgrade_https_to_http'];
        }

        // One resolution per hop; EVERY answer must pass — a mixed response
        // with a single private address (DNS rebinding) blocks the hop.
        $ips = $this->dnsLookup->resolveIps($host);
        if ($ips === []) {
            return ['ip' => null, 'reason' => 'redirect_nxdomain'];
        }

        foreach ($ips as $ip) {
            $verdict = $this->guard->classify($ip);
            if ($verdict->isBlocked()) {
                return ['ip' => null, 'reason' => 'ssrf_blocked:'.(string) $verdict->reason];
            }
        }

        return ['ip' => $ips[0], 'reason' => null];
    }
}
