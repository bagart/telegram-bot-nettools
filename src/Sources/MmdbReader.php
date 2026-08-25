<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

use BAGArt\TelegramBotNettools\Contracts\MmdbContract;

/**
 * MaxMind mmdb reader adapter (RFC §10.3): the `maxmind-db/reader` package is
 * approval-gated, so the adapter activates only when the class exists AND a
 * readable file is configured; otherwise every lookup returns null and probes
 * degrade to HTTP sources with a visible warning.
 *
 * @phpstan-import-type CityShape from \BAGArt\TelegramBotNettools\Contracts\MmdbContract
 */
final class MmdbReader implements MmdbContract
{
    /** @var array<string, object|null> path => lazy reader */
    private array $readers = [];

    public function __construct(
        private readonly ?string $cityPath,
        private readonly ?string $asnPath,
    ) {
    }

    /** config() that degrades to null without a Laravel container (tests). */
    private static function cfg(string $key): mixed
    {
        try {
            return config($key);
        } catch (\Throwable) {
            return null;
        }
    }

    public static function fromConfig(): self
    {
        return new self(
            cityPath: self::cfg('tg-nettools.mmdb.city'),
            asnPath: self::cfg('tg-nettools.mmdb.asn'),
        );
    }

    public function available(): bool
    {
        return $this->resolve($this->cityPath) !== null || $this->resolve($this->asnPath) !== null;
    }

    public function city(string $ip): ?array
    {
        $reader = $this->resolve($this->cityPath);

        return $reader === null ? null : $this->shapeCity($this->lookup($reader, $ip));
    }

    public function asn(string $ip): ?array
    {
        $reader = $this->resolve($this->asnPath);

        return $reader === null ? null : $this->shapeAsn($this->lookup($reader, $ip));
    }

    private function resolve(?string $path): ?object
    {
        if ($path === null || ! is_file($path) || ! class_exists(\MaxMind\Db\Reader::class)) {
            return null;
        }

        return $this->readers[$path] ??= $this->openReader($path);
    }

    private function openReader(string $path): ?object
    {
        try {
            return new \MaxMind\Db\Reader($path);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function lookup(object $reader, string $ip): array
    {
        try {
            $record = $reader->get($ip);
        } catch (\Throwable) {
            return [];
        }

        return is_array($record) ? $record : [];
    }

    /**
     * @param  array<string, mixed>  $record
     * @return array{country: ?string, region: ?string, city: ?string, lat: float, lon: float}|null
     */
    private function shapeCity(array $record): ?array
    {
        $country = $record['country']['iso_code'] ?? null;
        if (! is_string($country) || $country === '') {
            return null;
        }

        return [
            'country' => $country,
            'region' => is_string($record['subdivisions'][0]['iso_code'] ?? null) ? $record['subdivisions'][0]['iso_code'] : null,
            'city' => is_string($record['city']['names']['en'] ?? null) ? $record['city']['names']['en'] : null,
            'lat' => round((float) ($record['location']['latitude'] ?? 0), 2),
            'lon' => round((float) ($record['location']['longitude'] ?? 0), 2),
        ];
    }

    /**
     * @param  array<string, mixed>  $record
     * @return array{asn: int, org: string}|null
     */
    private function shapeAsn(array $record): ?array
    {
        $asn = filter_var($record['autonomous_system_number'] ?? null, FILTER_VALIDATE_INT);
        if ($asn === false || $asn === null) {
            return null;
        }

        return [
            'asn' => $asn,
            'org' => is_string($record['autonomous_system_organization'] ?? null)
                ? (string) $record['autonomous_system_organization']
                : '',
        ];
    }
}
