<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Nettools Module
|--------------------------------------------------------------------------
|
| Auditor / admin toolkit (bagart/telegram-bot-nettools-module). The module ships
| DISABLED per bot (fail-closed); enable it with tg:module:enable nettools.
| These are platform defaults and operational limits.
|
*/

return [
    // Kill-switch per probe group
    'features' => [
        'recon' => true,    // ip, whois, dns, geo, asn
        'active' => true,   // ping, trace, os
        'audit' => true,    // ssl, sec, mail, subs, reco, report
        'portscan' => false, // admin-gated, default off
        'dnsbl' => false,   // admin-gated, default off
    ],

    // Telegram chat ids allowed to run admin-gated commands (/portscan,
    // /dnsbl) and to bypass quotas. "111,222" via env.
    'admin_chat_ids' => array_values(array_filter(array_map(
        'trim',
        explode(',', (string) env('NETTOOLS_ADMIN_CHAT_IDS', '')),
    ))),

    'quotas' => [
        // Units/day/user; probes cost their command weight in units
        'daily_units' => (int) env('NETTOOLS_DAILY_UNITS', 40),
        // Total units/day per chat — caps group abuse regardless of users
        'chat_ceiling' => (int) env('NETTOOLS_CHAT_CEILING', 150),
        // Per-chat overrides: chat_id => units
        'overrides' => [],
    ],

    // DNS resolvers used by the internal DnsClient (Phase 1+)
    'resolvers' => ['1.1.1.1', '8.8.8.8'],

    'timeouts' => [
        'rdap' => 5,
        'whois43' => 8,
        'dns' => 2,
        'http' => 5,
        'ping' => 4,
    ],

    'caps' => [
        'ping_packets' => 4,
        'trace_hops' => 15,
        // /port throttle (per user, per hour) consumed by Support\RateLimiter
        'port_rate_per_hour' => 20,
    ],

    // GeoLite2 mmdb paths; null = HTTP fallback sources
    'mmdb' => [
        'city' => env('NETTOOLS_MMDB_CITY'),
        'asn' => env('NETTOOLS_MMDB_ASN'),
    ],

    // NOTE: keys without consumers are deliberately NOT declared here
    // (removed 2026-08-25, audit P0-3 / P1-3):
    // - api_keys.{ipinfo,censys} — no client consumes them yet;
    //   reintroduce together with the consuming source client.
    // - rate_limits.{crtsh_rps,rdap_rps,whois43_rps} — no source-level
    //   throttler is wired yet; land the limiter with its first real
    //   consumer (planned RIPEstat BGP deep-dive), not before.
    // - timeouts.tls — TLS probes carry their own budgets; add back next to
    //   a reader if per-source tuning is ever needed.
    // - allow_private_targets_for_admins — declared SSRF bypass was never
    //   implemented (fail-closed stays); revisit only with an explicit,
    //   logged per-command design.
    // - caps.{subs_show,scan_ports}, wordlist_path, ui.{tools_per_row,
    //   detail_mode_default} — hardcoded in probes/UI today; add back only
    //   next to the code that reads them.

    'ui' => [
        // Heavy ops (/trace, /report, /portscan) ask for confirmation first
        'heavy_confirm' => true,
    ],

    'memory' => [
        'enabled' => true,
        // Remember hosts after successful probes (target memory, /my)
        'auto_capture' => true,
        // LRU cap per user; pinned targets exempt
        'max_targets' => 25,
    ],
];
