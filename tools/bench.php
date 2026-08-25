<?php

declare(strict_types=1);

/**
 * Nettools per-probe latency benchmark (RFC Phase 4.2).
 *
 * Runs every pure/format-heavy path over synthetic fixtures — zero egress,
 * zero binaries — and prints a latency table. Usage:
 *
 *   php misc/BAGArt/telegram-bot-nettools/tools/bench.php
 */

use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Probes\OsHeuristicProbe;
use BAGArt\TelegramBotNettools\Support\RecoEngine;
use BAGArt\TelegramBotNettools\Ui\{AsnCard, DnsCard, IpCard, MailCard, PingCard, PortCard, ReportCard, SslCard, SubsCard};

require __DIR__.'/../../../../vendor/autoload.php';

$iterations = 500;
$timings = [];

$bench = static function (string $name, callable $fn) use (&$timings, $iterations): void {
    $fn(); // warmup
    $start = hrtime(true);
    for ($i = 0; $i < $iterations; $i++) {
        $fn();
    }
    $timings[$name] = (hrtime(true) - $start) / 1e6 / $iterations;
};

$probeResult = function (string $name, array $payload) {
    return new \BAGArt\TelegramBotNettools\Results\ProbeResult(
        probe: $name,
        fetchedAt: 0,
        latencyMs: 42,
        degradedSources: [],
        payload: $payload,
    );
};

$dnsPayload = [
    'host' => 'example.org',
    'records' => ['A' => ['93.184.216.34'], 'AAAA' => ['2606:2800:220:1:248:1893:25c8:1946'], 'MX' => ['10 mail.example.org'], 'NS' => ['a.iana-servers.net'], 'TXT' => ['v=spf1 -all']],
    'ttls' => ['A' => [3600], 'MX' => [300]],
    'statuses' => [],
    'dnssec_ad' => true,
    'authoritative' => false,
    'source_host' => '1.1.1.1',
];

$bench('HtmlRenderer.render', fn () => (new HtmlRenderer())->render('BENCH', [new \BAGArt\TelegramBotNettools\Formatting\Section('Group', ['line one', 'line two', str_repeat('x', 200)])]));
$bench('DnsProbe.payload->DnsCard', fn () => DnsCard::render($probeResult('dns', $dnsPayload), 1, time(), 'example.org'));
$bench('IpCard.render', fn () => IpCard::render($probeResult('ip', ['ip' => '93.184.216.34', 'country' => 'US', 'city' => 'LA', 'lat' => 34.05, 'lon' => -118.24, 'asn' => 15169, 'asn_org' => 'GOOGLE', 'type' => 'cloud', 'ptr' => 'edge.example.net', 'ptr_confirmed' => true, 'v6_reach' => 'reachable', 'source' => ['ip-api']]), 1, time(), '93.184.216.34'));
$bench('PingCard.render', fn () => PingCard::render($probeResult('ping', ['sent' => 4, 'received' => 4, 'loss_pct' => 0.0, 'min_ms' => 10.0, 'avg_ms' => 11.2, 'max_ms' => 13.4, 'jitter_ms' => 0.8, 'mode' => 'icmp', 'replies' => [['seq' => 1, 'ttl' => 56, 'ms' => 10.4]]]), 1, time(), 'example.org'));
$bench('PortCard.render', fn () => PortCard::render($probeResult('port', ['host' => 'example.org', 'port' => 443, 'state' => 'open', 'latency_ms' => 12.3, 'protocol' => 'https', 'banner' => "HTTP/1.1 200 OK\r\n"]), 1, time(), 'example.org'));
$bench('SslCard.render', fn () => SslCard::render($probeResult('ssl', ['host' => 'example.org', 'has_tls' => true, 'error' => null, 'protocol' => 'TLS1.3', 'alpn' => ['h2'], 'cert' => ['subject_cn' => 'example.org', 'issuer_org' => "Let's Encrypt", 'san' => ['example.org'], 'valid_from' => time() - 86400, 'valid_to' => time() + 60 * 86400, 'days_left' => 60, 'sig_alg' => 'sha256WithRSA', 'key_alg' => 'RSA', 'key_bits' => 2048, 'serial' => '04', 'sha256_fp' => str_repeat('ab', 32)], 'chain_count' => 2, 'self_signed' => false, 'ocsp_stapled' => false, 'offered_protocols' => ['TLS1.2', 'TLS1.3'], 'findings' => []]), 1, time(), 'example.org'));
$bench('MailCard.render', fn () => MailCard::render($probeResult('mail', ['host' => 'example.org', 'mx' => [['priority' => 10, 'host' => 'mail.example.org', 'ip_literal' => false, 'is_cname' => false]], 'spf' => ['record' => 'v=spf1 -all', 'lookups' => 0, 'errors' => [], 'multiple' => false], 'dmarc' => ['policy' => 'reject', 'rua' => true, 'pct' => 100, 'missing' => false, 'errors' => []], 'dkim' => ['mail'], 'mta_sts' => ['present' => true, 'id' => 'a'], 'tls_rpt' => 'rua@example.org', 'bimi' => false, 'findings' => []]), 1, time(), 'example.org'));
$bench('SubsCard.render', fn () => SubsCard::render($probeResult('subs', ['host' => 'example.com', 'wildcard' => false, 'resolved' => [['name' => 'www', 'ips' => ['93.184.216.34'], 'cname' => null, 'suspect' => null]], 'counts' => ['ct' => 5, 'brute_resolved' => 1, 'brute_queried' => 100], 'source_counts' => ['crt.sh' => 5], 'suspect_takeover' => [], 'truncated' => false]), 1, time(), 'example.com'));
$bench('AsnCard.render', fn () => AsnCard::render($probeResult('asn', ['asn' => 15169, 'org' => 'Google LLC', 'country' => 'US', 'registry' => 'ARIN', 'allocated' => '2000-03-30', 'prefixes' => ['8.8.8.0/24', '8.8.4.0/24'], 'prefix_counts' => ['v4' => 2, 'v6' => 1], 'rpki' => 'valid', 'peers' => [['asn' => 15169, 'holder' => 'GOOGLE', 'power' => 4000]], 'source' => ['ripestat']]), 1, time(), 'AS15169'));
$bench('RecoEngine.evaluate', function () use ($probeResult, $dnsPayload) {
    (new RecoEngine())->evaluate(['dns' => $probeResult('dns', $dnsPayload)]);
});
$bench('ReportCard.render', fn () => ReportCard::render('example.org', 900, [
    'dns' => $probeResult('dns', $dnsPayload),
    'http' => $probeResult('http', ['host' => 'example.org', 'error' => null, 'status' => 200, 'findings' => []]),
], ['dns:1.1.1.1'], [], null));
$bench('OsHeuristic.fuse', function () {
    $probe = new OsHeuristicProbe([]);
    $ref = new ReflectionMethod($probe, 'fuse');
    $ref->setAccessible(true);
    $ref->invoke($probe, [
        ['kind' => 'ttl', 'guesses' => [['family' => 'Linux/BSD', 'detail' => 'ttl 56']]],
        ['kind' => 'http-banner', 'guesses' => [['family' => 'Linux/BSD', 'detail' => 'nginx']]],
    ]);
});

printf("iterations=%d\n%s\n", $iterations, str_repeat('-', 46));
foreach ($timings as $name => $ms) {
    printf("%-28s %8.3f ms/op\n", $name, $ms);
}

unset($timings['HtmlRenderer.render']);
echo "\nformatting budget check: ", max($timings) < 1.0 ? 'PASS (<1 ms/op)' : 'WARN';
echo "\n";
