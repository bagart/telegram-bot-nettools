<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBotNettools\Contracts\DnsResolverContract;

/**
 * Thin resolution seam over PHP's DNS functions. Phase 0 stop-gap — Phase 1
 * replaces it with the internal DnsClient (RFC D5) behind the same call shape.
 */
final class DnsLookup implements DnsResolverContract
{
    /** @return list<string> resolved addresses; empty = no answers */
    public function resolveIps(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }

        $ips = [];

        foreach ([DNS_A, DNS_AAAA] as $type) {
            $records = @dns_get_record($host, $type);
            if ($records === false) {
                continue;
            }
            foreach ($records as $record) {
                $ip = $record['ip'] ?? $record['ipv6'] ?? null;
                if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                    $ips[$ip] = true;
                }
            }
        }

        if ($ips === []) {
            // gethostbyname covers resolvers that hide A records from
            // dns_get_record (some local stub resolvers)
            $v4 = @gethostbyname($host);
            if (is_string($v4) && $v4 !== $host && filter_var($v4, FILTER_VALIDATE_IP) !== false) {
                $ips[$v4] = true;
            }
        }

        return array_keys($ips);
    }
}
