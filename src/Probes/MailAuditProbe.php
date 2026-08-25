<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Sources\DnsAnswer;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Support\MailRecordsParser;

/**
 * /mail deliverability audit (§7.9): MX sanity, SPF lookup counting,
 * DMARC grading, DKIM selector probing, MTA-STS/TLS-RPT/BIMI presence.
 * Missing records ARE findings — this probe never throws for absence.
 */
final class MailAuditProbe implements NettoolsProbeContract
{
    /** Hard query budget per run (§7.9: ~14). */
    public const int MAX_QUERIES = 14;

    public const int MAX_DKIM_HITS = 2;

    /** @var list<string> */
    public const array DKIM_SELECTORS = ['mail', 'default', 'google', 'selector1', 'k1', 's1', 'dkim'];

    /**
     * @param  list<string>  $resolvers
     * @param  (\Closure(string): array{reachable: bool, starttls: bool, cert_days_left: ?int, error: string})|null  $smtpCheck
     */
    public function __construct(
        private readonly DnsClient $dns,
        private readonly array $resolvers,
        private readonly int $timeoutSeconds = 2,
        private readonly ?\Closure $smtpCheck = null,
    ) {
    }

    public function name(): string
    {
        return 'mail';
    }
    /** Highest-priority MX host for the live SMTP check ('--smtp' path). */
    public function primaryMxHost(string $host): ?string
    {
        $answer = null;
        foreach ($this->resolvers as $resolver) {
            $answer = $this->dns->query($resolver, strtolower(rtrim($host, '.')), 'MX', max(1, min(5, $this->timeoutSeconds)));
            if ($answer !== null && ($answer->records['MX'] ?? []) !== []) {
                break;
            }
        }

        if ($answer === null) {
            return null;
        }

        foreach ((array) ($answer->records['MX'] ?? []) as $mx) {
            // "10 mail.example.com." — lowest priority number wins
            if (preg_match('/^(\d+)\s+(\S+)$/', trim((string) $mx), $m)) {
                return rtrim($m[2], '.');
            }
        }

        return null;
    }



    public function ttlSeconds(): int
    {
        return 3600;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        unset($options);

        $host = strtolower(rtrim($target->host, '.'));
        $timeout = max(1, min(5, $this->timeoutSeconds));

        $queries = 0;
        $degraded = [];
        $txtByName = [];

        $ask = function (string $name, string $type) use (&$queries, &$degraded, $timeout): ?DnsAnswer {
            if ($queries >= self::MAX_QUERIES) {
                return null;
            }
            $queries++;

            foreach ($this->resolvers as $resolver) {
                $answer = $this->dns->query($resolver, $name, $type, $timeout);
                if ($answer !== null) {
                    return $answer; // first resolver wins per type
                }
                $degraded[$resolver] = true;
            }

            return null;
        };

        // Fixed base queries, then MX sanity, then bounded DKIM guesses.
        $mxAnswer = $ask($host, 'MX');
        $txtByName[''] = $ask($host, 'TXT')?->records['TXT'] ?? [];
        $dmarcTxts = $ask('_dmarc.'.$host, 'TXT')?->records['TXT'] ?? [];
        $stsTxts = $ask('_mta-sts.'.$host, 'TXT')?->records['TXT'] ?? [];
        $tlsRptTxts = $ask('_smtp._tls.'.$host, 'TXT')?->records['TXT'] ?? [];

        $mx = self::parseMx($mxAnswer?->records['MX'] ?? []);
        $firstMxHost = $mx[0]['host'] ?? null;
        if (is_string($firstMxHost) && ! $mx[0]['ip_literal']) {
            $cnameAnswer = $ask($firstMxHost, 'CNAME');
            $isCname = $cnameAnswer !== null && isset($cnameAnswer->records['CNAME']);
            $ask($firstMxHost, 'A'); // resolution sanity for the primary exchange
            if ($isCname) {
                $mx[0]['is_cname'] = true;
            }
        }

        $allTxts = [...$txtByName[''], ...$dmarcTxts, ...$stsTxts, ...$tlsRptTxts];
        [$dkimSelectors, $dkimTxts] = $this->probeDkim($host, $ask);
        $allTxts = [...$allTxts, ...$dkimTxts];

        [$spfPayload, $spfFindings] = self::auditSpf(self::recordsWithTag($txtByName[''], 'v=spf1'));
        [$dmarcPayload, $dmarcFindings] = self::auditDmarc(self::recordsWithTag($dmarcTxts, 'v=dmarc1'));

        $findings = [...$spfFindings, ...$dmarcFindings, ...self::auditMx($mx)];

        $stsRecord = self::recordsWithTag($stsTxts, 'v=stsv1')[0] ?? null;
        $mtaSts = ['present' => $stsRecord !== null, 'id' => null, 'policy_fetched' => false];
        if (is_string($stsRecord) && preg_match('/\bid\s*=\s*([^;\s]+)/i', $stsRecord, $m) === 1) {
            $mtaSts['id'] = $m[1];
        } elseif ($stsRecord === null) {
            $findings[] = self::finding('info', 'mta_sts_absent', 'no MTA-STS record (_mta-sts TXT v=STSv1)');
        }

        $tlsRptRecord = self::recordsWithTag($tlsRptTxts, 'v=tlsrptv1')[0] ?? null;
        $tlsRua = is_string($tlsRptRecord)
            && preg_match('/\brua\s*=\s*([^;\s]+)/i', $tlsRptRecord, $m) === 1 ? $m[1] : null;
        if ($tlsRptRecord === null) {
            $findings[] = self::finding('info', 'tls_rpt_absent', 'no TLS-RPT record (_smtp._tls TXT v=TLSRPTv1)');
        }

        // BIMI is presence-only — recorded in the payload, never a finding.
        $bimi = self::hasTag($allTxts, 'v=bimi1');

        if ($dkimSelectors === []) {
            $findings[] = self::finding('info', 'dkim_absent', 'no DKIM key found under probed selectors ('.implode(', ', self::DKIM_SELECTORS).')');
        }

        $smtp = null;
        if ($this->smtpCheck !== null && $firstMxHost !== null) {
            try {
                $check = ($this->smtpCheck)($firstMxHost);
            } catch (\Throwable) {
                $check = ['reachable' => false, 'starttls' => false, 'cert_days_left' => null, 'error' => 'SMTP check failed'];
            }
            $smtp = [
                'reachable' => (bool) ($check['reachable'] ?? false),
                'starttls' => (bool) ($check['starttls'] ?? false),
                'cert_days_left' => isset($check['cert_days_left']) && is_int($check['cert_days_left']) ? $check['cert_days_left'] : null,
                'error' => (string) ($check['error'] ?? ''),
            ];
            if ($smtp['reachable'] && ! $smtp['starttls']) {
                $findings[] = self::finding('high', 'starttls_missing', "primary MX {$firstMxHost} does not offer STARTTLS");
            }
        }

        $rank = ['high' => 0, 'warn' => 1, 'info' => 2];
        usort($findings, fn (array $a, array $b): int => [$rank[$a['severity']], $a['id']] <=> [$rank[$b['severity']], $b['id']]);

        $payload = [
            'host' => $host,
            'mx' => $mx,
            'spf' => $spfPayload,
            'dmarc' => $dmarcPayload,
            'dkim' => $dkimSelectors,
            'mta_sts' => $mtaSts,
            'tls_rpt' => $tlsRua,
            'bimi' => $bimi,
            'findings' => $findings,
        ];
        if ($smtp !== null) {
            $payload['smtp'] = $smtp;
        }

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: 0,
            degradedSources: array_keys($degraded),
            payload: $payload,
        );
    }

    /**
     * @param  \Closure(string, string): ?DnsAnswer  $ask
     * @return array{0: list<string>, 1: list<string>}
     */
    private function probeDkim(string $host, \Closure $ask): array
    {
        $found = [];
        $txts = [];

        foreach (self::DKIM_SELECTORS as $selector) {
            $answer = $ask($selector.'._domainkey.'.$host, 'TXT');
            if ($answer === null || empty($answer->records['TXT'])) {
                continue;
            }
            $found[] = $selector;
            $txts = [...$txts, ...$answer->records['TXT']];
            if (count($found) >= self::MAX_DKIM_HITS) {
                break;
            }
        }

        return [$found, $txts];
    }

    /** @param list<string> $values */
    private static function recordsWithTag(array $values, string $tag): array
    {
        return array_values(array_filter(
            $values,
            static fn (mixed $value): bool => is_string($value) && str_starts_with(strtolower(ltrim($value)), $tag),
        ));
    }

    /** @param list<string> $values */
    private static function hasTag(array $values, string $tag): bool
    {
        return self::recordsWithTag($values, $tag) !== [];
    }

    /** @param list<string> $rawMx "pref host" strings from DnsClient */
    private static function parseMx(array $rawMx): array
    {
        $mx = [];
        foreach ($rawMx as $value) {
            $parts = explode(' ', trim((string) $value), 2);
            $exchange = trim($parts[1] ?? '');
            if ($exchange === '') {
                continue;
            }
            $mx[] = [
                'priority' => (int) $parts[0],
                'host' => $exchange,
                'ip_literal' => filter_var($exchange, FILTER_VALIDATE_IP) !== false,
                'is_cname' => false,
            ];
        }
        usort($mx, fn (array $a, array $b): int => $a['priority'] <=> $b['priority']);

        return $mx;
    }

    private static function auditSpf(array $spfRecords): array
    {
        if ($spfRecords === []) {
            return [null, [self::finding('high', 'spf_missing', 'no SPF record at the apex (TXT v=spf1)')]];
        }

        $parsed = MailRecordsParser::parseSpf((string) $spfRecords[0]);
        $multiple = count($spfRecords) > 1;
        $payload = [
            'record' => (string) $spfRecords[0],
            'lookups' => $parsed['lookups'],
            'errors' => $parsed['errors'],
            'multiple' => $multiple,
        ];

        $findings = [];
        if ($multiple) {
            $findings[] = self::finding('high', 'spf_multiple', count($spfRecords).' SPF records published — RFC 7208 requires exactly one');
        }
        if ($parsed['lookups'] > MailRecordsParser::SPF_LOOKUP_LIMIT) {
            $findings[] = self::finding('warn', 'spf_lookups_exceeded', "{$parsed['lookups']} DNS-consuming terms exceed the RFC 7208 limit of ".MailRecordsParser::SPF_LOOKUP_LIMIT);
        }
        if ($parsed['errors'] !== []) {
            $findings[] = self::finding('warn', 'spf_syntax', 'SPF syntax: '.implode('; ', $parsed['errors']));
        }

        return [$payload, $findings];
    }

    private static function auditDmarc(array $dmarcRecords): array
    {
        if ($dmarcRecords === []) {
            $payload = ['policy' => null, 'rua' => false, 'pct' => null, 'missing' => true, 'errors' => []];

            return [$payload, [self::finding('warn', 'dmarc_missing', 'no DMARC record at _dmarc (TXT v=DMARC1)')]];
        }

        $graded = MailRecordsParser::gradeDmarc((string) $dmarcRecords[0]);
        $payload = [...$graded, 'missing' => false];

        $findings = [];
        if ($graded['policy'] === null) {
            $detail = 'DMARC record unparsable'.($graded['errors'] !== [] ? ': '.implode('; ', $graded['errors']) : '');
            $findings[] = self::finding('warn', 'dmarc_missing', $detail);
        } elseif ($graded['policy'] === 'none') {
            $findings[] = self::finding('warn', 'dmarc_none_policy', 'p=none monitors only — move up the ladder none → quarantine → reject');
        }

        return [$payload, $findings];
    }

    /** @param list<array{priority: int, host: string, ip_literal: bool, is_cname: bool}> $mx */
    private static function auditMx(array $mx): array
    {
        $findings = [];
        foreach ($mx as $entry) {
            if ($entry['ip_literal']) {
                $findings[] = self::finding('high', 'mx_ip_literal', "MX {$entry['host']} is an IP literal — RFC 5321 §5.1 requires a hostname");
            }
            if ($entry['is_cname']) {
                $findings[] = self::finding('high', 'mx_cname', "MX {$entry['host']} is a CNAME alias — RFC 2181 §10.3 violation");
            }
        }

        return $findings;
    }

    /** @return array{severity: string, id: string, detail: string} */
    private static function finding(string $severity, string $id, string $detail): array
    {
        return ['severity' => $severity, 'id' => $id, 'detail' => $detail];
    }
}
