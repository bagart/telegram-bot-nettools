<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

use BAGArt\TelegramBotNettools\Contracts\SourceHttpContract;

/**
 * RIPEstat data API (tertiary geo/ASN source + primary ASN enrichment:
 * announced prefixes, neighbours). Free, keyless; breaker-guarded.
 */
final class RipestatSource
{
    public const string NAME = 'ripestat';

    public function __construct(private readonly SourceHttpContract $http)
    {
    }

    /** IP/ASN → {asn: "AS15169", holder, block} | null */
    public function networkInfo(string $resource): ?array
    {
        return $this->data('network-info', $resource);
    }

    /** ASN → prefix-overview payload (asns[], block{}) | null */
    /** RPKI ROA status for a resource (RFC §7.3): valid|invalid|not_found|null. */
    public function rpkiFor(string $resource): ?string
    {
        $body = $this->http->getJson(
            'https://stat.ripe.net/data/rpki-validation/data.json?resource='.rawurlencode($resource).'&sourceapp=telegram-bot-nettools',
            3,
        );

        if ($body === null) {
            return null;
        }

        return match ((string) ($body['data']['status'] ?? '')) {
            'valid' => 'valid',
            'invalid' => 'invalid',
            default => 'not_found',
        };
    }

    public function prefixOverview(string $asn): ?array
    {
        return $this->data('prefix-overview', $asn);
    }

    /**
     * ASN → list<array{prefix: string}> of announced prefixes.
     *
     * @return list<string>|null
     */
    public function announcedPrefixes(string $asn): ?array
    {
        $body = $this->data('announced-prefixes', $asn);
        if ($body === null) {
            return null;
        }

        $prefixes = [];
        foreach ((array) ($body['prefixes'] ?? []) as $entry) {
            if (is_string($entry['prefix'] ?? null)) {
                $prefixes[] = $entry['prefix'];
            }
        }

        return array_values(array_unique($prefixes));
    }

    /**
     * ASN → neighbours sorted by peering power desc.
     *
     * @return list<array{asn: int, holder: string, power: int}>|null
     */
    public function neighbours(string $asn): ?array
    {
        $body = $this->data('asn-neighbours', $asn);
        if ($body === null) {
            return null;
        }

        $neighbours = [];
        foreach ((array) ($body['neighbours'] ?? []) as $entry) {
            $peerAsn = filter_var($entry['asn'] ?? null, FILTER_VALIDATE_INT);
            if ($peerAsn === false || $peerAsn === 0) {
                continue;
            }
            $neighbours[] = [
                'asn' => $peerAsn,
                'holder' => is_string($entry['holder'] ?? null) ? $entry['holder'] : '',
                'power' => (int) ($entry['power'] ?? 0),
            ];
        }

        usort($neighbours, static fn (array $a, array $b): int => $b['power'] <=> $a['power']);

        return $neighbours;
    }

    /**
     * @return array<string, mixed>|null inner `data` document or null
     */
    private function data(string $endpoint, string $resource): ?array
    {
        $url = 'https://stat.ripe.net/data/'.$endpoint.'/data.json?sourceapp=telegram-bot-nettools&resource='.rawurlencode($resource);

        return $this->http->getJson($url, 4)['data'] ?? null;
    }
}
