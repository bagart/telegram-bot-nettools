<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools;

/**
 * Normalized config snapshot (RFC §9) resolved once per command build.
 * Keeps config() out of processors so they are testable without Laravel.
 */
final readonly class NettoolsSettings
{
    public function __construct(
        public bool $reconEnabled = true,
        public bool $activeEnabled = true,
        public bool $auditEnabled = true,
        public bool $portscanEnabled = false,
        public bool $dnsblEnabled = false,
        public int $timeoutRdap = 5,
        public int $timeoutWhois43 = 8,
        public int $timeoutDns = 2,
        public int $timeoutHttpFetch = 5,
        public int $timeoutPing = 4,
        public int $pingPackets = 4,
        public int $traceHops = 15,
        public int $portRatePerHour = 20,
        public bool $heavyConfirm = true,
        public bool $memoryEnabled = true,
        public bool $autoCapture = true,
        public int $maxTargets = 25,
    ) {
    }

    /** @param array<string, mixed> $cfg config('tg-nettools') tree */
    public static function fromArray(array $cfg): self
    {
        $features = (array) ($cfg['features'] ?? []);
        $timeouts = (array) ($cfg['timeouts'] ?? []);
        $caps = (array) ($cfg['caps'] ?? []);
        $ui = (array) ($cfg['ui'] ?? []);

        return new self(
            reconEnabled: (bool) ($features['recon'] ?? true),
            activeEnabled: (bool) ($features['active'] ?? true),
            auditEnabled: (bool) ($features['audit'] ?? true),
            portscanEnabled: (bool) ($features['portscan'] ?? false),
            dnsblEnabled: (bool) ($features['dnsbl'] ?? false),
            timeoutRdap: (int) ($timeouts['rdap'] ?? 5),
            timeoutWhois43: (int) ($timeouts['whois43'] ?? 8),
            timeoutDns: (int) ($timeouts['dns'] ?? 2),
            timeoutHttpFetch: (int) ($timeouts['http'] ?? 5),
            timeoutPing: (int) ($timeouts['ping'] ?? 4),
            pingPackets: max(1, min(10, (int) ($caps['ping_packets'] ?? 4))),
            traceHops: max(1, min(30, (int) ($caps['trace_hops'] ?? 15))),
            portRatePerHour: (int) ($caps['port_rate_per_hour'] ?? 20),
            heavyConfirm: (bool) ($ui['heavy_confirm'] ?? true),
            memoryEnabled: (bool) (($cfg['memory'] ?? [])['enabled'] ?? true),
            autoCapture: (bool) (($cfg['memory'] ?? [])['auto_capture'] ?? true),
            maxTargets: max(1, min(100, (int) (($cfg['memory'] ?? [])['max_targets'] ?? 25))),
        );
    }

    public static function fromConfig(): self
    {
        try {
            return self::fromArray((array) config('tg-nettools'));
        } catch (\Throwable) {
            return new self();
        }
    }
}
