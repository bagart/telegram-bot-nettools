<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Ui;

final class CommandCatalog
{
    /** @return list<CommandCatalogEntry> full catalog in RFC §3.1 order */
    public static function all(): array
    {
        $e = static fn (string $n, string $d, int $w, bool $s): CommandCatalogEntry => new CommandCatalogEntry($n, $d, $w, $s);

        return [
            $e('nt', 'menu hub and help', 0, true),
            $e('quota', 'remaining budget in this chat', 0, true),
            $e('my', 'remembered targets', 0, true),
            $e('r', 'repeat last command', 0, true),
            $e('ip', 'geo, ASN, rDNS (alias: /geo)', 1, true),
            $e('asn', 'ASN card: org, prefixes, peers', 1, true),
            $e('whois', 'registrar, dates, statuses', 2, true),
            $e('dns', 'record matrix + diagnostics', 1, true),
            $e('mail', 'MX/SPF/DMARC/DKIM audit', 1, true),
            $e('subs', 'subdomain enumeration', 3, true),
            $e('http', 'availability & speed snapshot', 1, true),
            $e('port', 'single-port reachability', 1, true),
            $e('ping', 'loss/latency/jitter', 1, true),
            $e('trace', 'traceroute with ASN per hop', 4, true),
            $e('os', 'stack fingerprint heuristics', 2, true),
            $e('ssl', 'certificate audit', 2, true),
            $e('sec', 'security headers audit', 1, true),
            $e('reco', 'recommendations scorecard', 2, true),
            $e('report', 'aggregated mega-report', 8, true),
            $e('portscan', 'admin TCP connect scan', 10, false),
            $e('dnsbl', 'admin DNSBL listing check', 2, false),
        ];
    }

    /** @return list<CommandCatalogEntry> */
    public static function shipped(): array
    {
        return array_values(array_filter(self::all(), static fn (CommandCatalogEntry $entry) => $entry->shipped));
    }
}
