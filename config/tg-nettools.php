<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Nettools Module
|--------------------------------------------------------------------------
|
| Auditor / admin toolkit (bagart/telegram-bot-nettools). The module ships
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
        'tls' => 3,
    ],

    'caps' => [
        'ping_packets' => 4,
        'trace_hops' => 15,
        'subs_show' => 200,
        'scan_ports' => 100,
    ],

    // Custom wordlist path; null = bundled list (Phase 2)
    'wordlist_path' => null,

    // GeoLite2 mmdb paths; null = HTTP fallback sources
    'mmdb' => [
        'city' => env('NETTOOLS_MMDB_CITY'),
        'asn' => env('NETTOOLS_MMDB_ASN'),
    ],

    'api_keys' => [
        'ipinfo' => env('NETTOOLS_IPINFO_KEY'),
        'censys' => env('NETTOOLS_CENSYS_KEY'),
    ],

    'rate_limits' => [
        'crtsh_rps' => (float) env('NETTOOLS_CRTSH_RPS', 0.5),
        'rdap_rps' => (float) env('NETTOOLS_RDAP_RPS', 1.0),
        'whois43_rps' => (float) env('NETTOOLS_WHOIS43_RPS', 0.5),
    ],

    // Admin chats may allowlist private/reserved targets (SSRF matrix bypass)
    'allow_private_targets_for_admins' => false,

    'ui' => [
        'tools_per_row' => 3,
        // Heavy ops (/trace, /report, /portscan) ask for confirmation first
        'heavy_confirm' => true,
        'detail_mode_default' => 'compact',
    ],

    'memory' => [
        'enabled' => true,
        // Remember hosts after successful probes (target memory, /my)
        'auto_capture' => true,
        // LRU cap per user; pinned targets exempt
        'max_targets' => 25,
    ],
];
