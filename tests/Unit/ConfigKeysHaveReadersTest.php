<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Config-shape lock (todo.nettools P0-3 gate): every leaf in
 * config/tg-nettools.php must have a declared reader — dead keys are
 * forbidden. Nested subtrees consumed wholesale via config('tg-nettools')
 * are attributed to NettoolsSettings::fromArray().
 *
 * Both directions are asserted: a key removed from the config but still
 * expected here fails, and any newly added unread key fails.
 */
final class ConfigKeysHaveReadersTest extends TestCase
{
    /** path → where it is read (literal dotted key or the settings-tree note) */
    private const array READERS = [
        'features.recon' => 'NettoolsSettings::fromArray() [config(\'tg-nettools\') tree]',
        'features.active' => 'NettoolsSettings::fromArray()',
        'features.audit' => 'NettoolsSettings::fromArray()',
        'features.portscan' => 'NettoolsSettings::fromArray()',
        'features.dnsbl' => 'NettoolsSettings::fromArray()',
        'admin_chat_ids' => 'QuotaLedger::fromConfig()',
        'quotas.daily_units' => 'QuotaLedger::fromConfig()',
        'quotas.chat_ceiling' => 'QuotaLedger::fromConfig()',
        'quotas.overrides' => 'QuotaLedger::fromConfig()',
        'resolvers' => 'NettoolsServices::resolvers()/DnsProbe/DnsblProbe/SubsCommand',
        'timeouts.rdap' => 'NettoolsSettings::fromArray()',
        'timeouts.whois43' => 'NettoolsSettings::fromArray()',
        'timeouts.dns' => 'NettoolsSettings::fromArray()',
        'timeouts.http' => 'NettoolsSettings::fromArray()',
        'timeouts.ping' => 'NettoolsSettings::fromArray()',
        'caps.ping_packets' => 'NettoolsSettings::fromArray()',
        'caps.trace_hops' => 'NettoolsSettings::fromArray()',
        'caps.port_rate_per_hour' => 'NettoolsSettings::fromArray() → PortCommand/RateLimiter',
        'mmdb.city' => 'MmdbReader::fromConfig()',
        'mmdb.asn' => 'MmdbReader::fromConfig()',
        'ui.heavy_confirm' => 'NettoolsSettings::fromArray()',
        'memory.enabled' => 'NettoolsSettings::fromArray()',
        'memory.auto_capture' => 'NettoolsSettings::fromArray()',
        'memory.max_targets' => 'NettoolsSettings::fromArray()',
    ];

    public function test_every_config_leaf_has_a_declared_reader(): void
    {
        self::assertSame(
            [],
            array_diff($this->configLeafPaths(), array_keys(self::READERS)),
            'config keys without a reader appeared — wire a consumer or extend READERS',
        );
    }

    public function test_every_declared_reader_still_maps_to_a_config_key(): void
    {
        self::assertSame(
            [],
            array_diff(array_keys(self::READERS), $this->configLeafPaths()),
            'declared reader points at a removed key — drop the entry and its consumer',
        );
    }

    /** @return list<string> dotted paths of every scalar/list leaf */
    private function configLeafPaths(): array
    {
        $paths = [];
        foreach ($this->config() as $key => $value) {
            $this->walk((string) $key, $value, $paths);
        }

        return $paths;
    }

    private function walk(string $path, mixed $value, array &$paths): void
    {
        if (is_array($value) && $value !== [] && ! array_is_list($value)) {
            foreach ($value as $child => $leaf) {
                $this->walk($path.'.'.(string) $child, $leaf, $paths);
            }

            return;
        }

        $paths[] = $path;
    }

    /** @return array<string, mixed> */
    private function config(): array
    {
        if (! function_exists('env')) {
            require_once __DIR__.'/../Support/env_stub.php';
        }

        /** @var array<string, mixed> $config */
        $config = require __DIR__.'/../../config/tg-nettools.php';

        return $config;
    }
}
