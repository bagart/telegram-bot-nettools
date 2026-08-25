<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBotNettools\Results\ProbeResult;

/**
 * Deterministic recommendations engine (RFC §8): table-driven rules over a
 * ReportContext of probe results. Same input → byte-identical output.
 *
 * Grading: score starts at 100; high −15, warn −5, info −1;
 * A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50.
 */
final class RecoEngine
{
    private const array DEDUCTION = ['high' => 15, 'warn' => 5, 'info' => 1];

    /**
     * Probe findings already carry severity+detail; this map adds the fix hint.
     */
    private const array HINTS = [
        // DNS
        'dnssec_absent' => 'sign the zone; upload the DS record at your registrar',
        'caa_absent' => 'add a CAA record restricting issuance to your CA',
        'ipv6_absent' => 'publish AAAA records; test with happy-eyeballs',
        // Mail
        'spf_missing' => 'publish v=spf1 with minimal includes',
        'spf_lookups_exceeded' => 'flatten or replace includes to get under 10 lookups',
        'spf_multiple' => 'merge into a single SPF record',
        'dmarc_missing' => 'start at p=none with rua reports, then ladder up',
        'dmarc_none_policy' => 'move DMARC to quarantine with rua reports',
        'mx_ip_literal' => 'point MX at a hostname per RFC 5321',
        'mx_cname' => 'MX must not point at a CNAME — use an A/AAAA target',
        'mta_sts_absent' => 'publish _mta-sts TXT + policy to enforce SMTP TLS',
        'tls_rpt_absent' => 'publish _smtp._tls TXT with rua to see delivery failures',
        'dkim_absent' => 'publish DKIM under standard selectors (mail, default, s1…)',
        'starttls_missing' => 'enable TLS on the mail exchanger',
        // Web/TLS
        'no_hsts' => 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
        'hsts_no_max_age' => 'set an explicit HSTS max-age',
        'hsts_low_max_age' => 'raise HSTS max-age to ≥15552000 (180d)',
        'no_csp' => 'start with report-only CSP, then enforce',
        'no_xfo' => 'set X-Frame-Options: DENY (or frame-ancestors)',
        'no_xcto' => 'set X-Content-Type-Options: nosniff',
        'no_referrer_policy' => 'set Referrer-Policy: strict-origin-when-cross-origin',
        'version_banner' => 'suppress version strings in Server/X-Powered-By headers',
        'expired' => 'renew immediately — the certificate has expired',
        'not_valid_yet' => 'certificate clock mismatch — reissue',
        'expiring_soon' => 'renew now; automate via ACME cron',
        'legacy_protocol' => 'disable TLS 1.0/1.1 on the endpoint',
        'weak_sig' => 'reissue with SHA-256 signature',
        'weak_key' => 'reissue with RSA ≥2048 or EC P-256',
        'self_signed' => 'issue a CA-signed certificate for public hosts',
        'hostname_mismatch' => 'issue a certificate covering the exact hostnames served',
        'incomplete_chain' => 'serve the full intermediate chain',
        'long_lifetime' => 'shorten certificate lifetime; automate via ACME',
        // §8 additions wired from probe findings
        'security_txt_missing' => 'publish /.well-known/security.txt with an RFC 9116 contact',
        'cors_wildcard_credentials' => 'restrict origins; never combine ACAO:* with credentials=true',
        'cors_origin_reflection' => 'allowlist exact origins instead of reflecting arbitrary ones',
        'trace_enabled' => 'disable legacy TRACE/TRACK methods at the web server',
        'hsts_not_preload_eligible' => 'raise max-age to ≥31536000 and add includeSubDomains',
        'no_compression' => 'enable brotli/gzip for text assets',
        'long_redirect_chain' => 'redirect directly instead of chaining >2 hops',
        'no_h2' => 'enable ALPN h2 on the TLS listener',
        'mta_sts_weak_mode' => 'move MTA-STS policy to enforce and publish reports',
    ];

    /**
     * Extra context rules evaluated from raw payloads (RFC §8 DNS/expiry
     * tables): [id, severity, appliesTo, predicate(ProbeResult payload)].
     *
     * @return list<array{0:string,1:'high'|'warn'|'info',2:string,3:callable}>
     */
    private static function contextRules(): array
    {
        return [
            ['caa_absent', 'warn', 'dns', static fn (array $p): bool => is_array($p['records'] ?? null)
                && ! isset($p['records']['CAA'])],
            ['ipv6_absent', 'info', 'dns', static fn (array $p): bool => is_array($p['records'] ?? null)
                && (! isset($p['records']['AAAA']) || $p['records']['AAAA'] === [])],
            ['dnssec_absent', 'warn', 'whois', static fn (array $p): bool => ($p['dnssec'] ?? null) === false
                || (($p['dnssec_ad'] ?? null) === false && ($p['dnssec'] ?? null) === null)],
        ];
    }

    /**
     * @param  array<string, ProbeResult>  $results  probe name → result
     * @return array{score:int, grade:string, passed:int, failed:int, findings:list<array{severity:string,id:string,detail:string,hint:string}>}
     */
    public function evaluate(array $results): array
    {
        $findings = [];
        $passed = 0;

        foreach ($results as $probeName => $result) {
            $payload = $result->payload;

            foreach ((array) ($payload['findings'] ?? []) as $finding) {
                $severity = (string) $finding['severity'];
                if ($severity === 'high') {
                    $findings[] = self::finding($probeName, $severity, (string) $finding['id'], (string) $finding['detail']);
                } else {
                    $findings[] = self::finding($probeName, $severity, (string) $finding['id'], (string) $finding['detail']);
                }
            }

            foreach (self::contextRules() as [$id, $severity, $appliesTo, $predicate]) {
                if ($appliesTo !== $probeName) {
                    continue;
                }

                try {
                    if ($predicate($payload)) {
                        $findings[] = self::finding($probeName, $severity, $id, self::defaultDetail($id));
                    } elseif (in_array($id, ['caa_absent', 'ipv6_absent', 'dnssec_absent'], true)) {
                        $passed++;
                    }
                } catch (\Throwable) {
                    continue;
                }
            }
        }

        usort($findings, static fn (array $a, array $b): int => [(string) $a['severity'], (string) $a['id']]
            <=> [(string) $b['severity'], (string) $b['id']]);

        $deduction = 0;
        foreach ($findings as $finding) {
            $deduction += self::DEDUCTION[(string) $finding['severity']] ?? 1;
        }

        $score = max(0, 100 - $deduction);

        return [
            'score' => $score,
            'grade' => match (true) {
                $score >= 90 => 'A',
                $score >= 80 => 'B',
                $score >= 65 => 'C',
                $score >= 50 => 'D',
                default => 'F',
            },
            'passed' => $passed,
            'failed' => count($findings),
            'findings' => $findings,
        ];
    }

    /** @return array{severity:string,id:string,detail:string,hint:string} */
    private static function finding(string $probe, string $severity, string $id, string $detail): array
    {
        return [
            'severity' => $severity,
            'id' => $id,
            'detail' => '['.$probe.'] '.$detail,
            'hint' => self::HINTS[$id] ?? 'review the finding in /report',
        ];
    }

    private static function defaultDetail(string $id): string
    {
        return match ($id) {
            'caa_absent' => 'No CAA record — any CA may issue for this domain',
            'ipv6_absent' => 'No AAAA record published',
            default => 'DNSSEC not enabled on the zone',
        };
    }
}
