<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts;

/**
 * Local MaxMind mmdb lookup seam (RFC §7.3/§7.15). The `maxmind-db/reader`
 * dependency is approval-gated (RFC §10.3): production wiring passes a reader
 * only when the package is installed and the configured file exists; callers
 * must treat null as "source unavailable" and degrade, never fail.
 *
 * @return arrays are scalar-only trees (cache-purity rule)
 */
/**
 * @phpstan-type CityShape array{country: ?string, region: ?string, city: ?string, lat: float, lon: float}
 * @phpstan-type AsnShape array{asn: int, org: string}
 */
interface MmdbContract
{
    /**
     * GeoLite2-City lookup.
     *
     * @return array{country: ?string, region: ?string, city: ?string, lat: float, lon: float}|null
     */
    public function city(string $ip): ?array;

    /**
     * GeoLite2-ASN lookup.
     *
     * @return array{asn: int, org: string}|null
     */
    public function asn(string $ip): ?array;
}
