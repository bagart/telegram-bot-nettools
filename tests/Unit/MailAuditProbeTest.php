<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Probes\MailAuditProbe;
use BAGArt\TelegramBotNettools\Results\GuardVerdict;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Support\MailRecordsParser;
use BAGArt\TelegramBotNettools\Tests\Support\FakeDnsTransport;
use BAGArt\TelegramBotNettools\Ui\MailCard;
use PHPUnit\Framework\TestCase;

/**
 * MailAuditProbe tests (§7.9): scripted-transport fixtures for the healthy
 * stack, SPF lookup-limit breach, multiple SPF, DMARC p=none, MX sanity,
 * DKIM selector probing; plus parser edge cases and JSON round-trip.
 */
final class MailAuditProbeTest extends TestCase
{
    private const string HOST = 'example.com';

    public function test_healthy_domain_has_no_high_findings_and_renders_card(): void
    {
        $transport = new FakeDnsTransport();

        // Query order: MX, TXT apex, _dmarc, _mta-sts, _smtp._tls,
        // CNAME/A on primary MX, then DKIM selectors (stop after 2 hits).
        $transport->script(['udp' => FakeDnsTransport::response(self::HOST, 15, [
            ['type' => 15, 'rdata' => pack('n', 10).FakeDnsTransport::name('mail.'.self::HOST)],
        ])]);
        $transport->script(['udp' => FakeDnsTransport::response(self::HOST, 16, [
            ['type' => 16, 'rdata' => self::txt('v=spf1 include:_spf.example.net -all')],
        ])]);
        $transport->script(['udp' => FakeDnsTransport::response('_dmarc.'.self::HOST, 16, [
            ['type' => 16, 'rdata' => self::txt('v=DMARC1; p=quarantine; rua=mailto:dmarc@agg.example.com; pct=100')],
        ])]);
        $transport->script(['udp' => FakeDnsTransport::response('_mta-sts.'.self::HOST, 16, [
            ['type' => 16, 'rdata' => self::txt('v=STSv1; id=20260101')],
        ])]);
        $transport->script(['udp' => FakeDnsTransport::response('_smtp._tls.'.self::HOST, 16, [
            ['type' => 16, 'rdata' => self::txt('v=TLSRPTv1; rua=mailto:tls-rpt@agg.example.com')],
        ])]);
        $transport->script(['udp' => FakeDnsTransport::response('mail.example.com', 5, [])]);
        $transport->script(['udp' => FakeDnsTransport::response('mail.example.com', 1, [
            ['type' => 1, 'rdata' => inet_pton('203.0.113.10')],
        ])]);
        $transport->script(['udp' => FakeDnsTransport::response('mail._domainkey.example.com', 16, [
            ['type' => 16, 'rdata' => self::txt('v=DKIM1; k=rsa; p=MIGfMA0GCS')],
        ])]);
        $transport->script(['udp' => FakeDnsTransport::response('default._domainkey.example.com', 16, [
            ['type' => 16, 'rdata' => self::txt('v=DKIM1; k=rsa; p=MIGfMA0GCS')],
        ])]);

        $result = $this->probe($transport)->probe($this->target(), new ProbeOptions(timeoutSeconds: 2));

        self::assertSame([], $result->degradedSources);
        self::assertSame([], $this->findingsWithSeverity($result, 'high'));
        self::assertSame(['mail', 'default'], $result->payload['dkim'], 'selector guessing stops after 2 hits');
        self::assertSame(9, count($transport->udpQueries), 'guessing stopped early');
        self::assertSame(1, $result->payload['spf']['lookups']);
        self::assertSame('quarantine', $result->payload['dmarc']['policy']);
        self::assertTrue($result->payload['dmarc']['rua']);
        self::assertSame('20260101', $result->payload['mta_sts']['id']);
        self::assertTrue($result->payload['mta_sts']['present']);
        self::assertSame('mailto:tls-rpt@agg.example.com', $result->payload['tls_rpt']);
        self::assertFalse($result->payload['bimi']);
        self::assertArrayNotHasKey('smtp', $result->payload, 'seam omitted → payload key omitted');
        self::assertFalse($result->payload['mx'][0]['is_cname']);

        $card = MailCard::render($result, 42, time(), self::HOST);
        self::assertStringContainsString('MAIL · example.com', $card['text']);
        self::assertLessThanOrEqual(3800, mb_strlen($card['text']));
    }

    public function test_spf_with_eleven_includes_breaches_lookup_limit(): void
    {
        $transport = new FakeDnsTransport();
        $includes = implode(' ', array_map(static fn (int $i): string => "include:_spf{$i}.example.net", range(1, 11)));
        $spf = "v=spf1 {$includes} -all";

        $transport->script(['udp' => FakeDnsTransport::response(self::HOST, 15, [])]);
        $transport->script(['udp' => FakeDnsTransport::response(self::HOST, 16, [
            ['type' => 16, 'rdata' => self::txtChunked($spf)],
        ])]);

        $result = $this->probe($transport)->probe($this->target(), new ProbeOptions(timeoutSeconds: 2));

        self::assertSame(11, $result->payload['spf']['lookups']);
        $warnings = $this->findingsById($result, 'spf_lookups_exceeded');
        self::assertCount(1, $warnings);
        self::assertSame('warn', $warnings[0]['severity']);
        self::assertStringContainsString('11', $warnings[0]['detail']);
    }

    public function test_multiple_spf_records_is_a_high_finding(): void
    {
        $transport = new FakeDnsTransport();
        $transport->script(['udp' => FakeDnsTransport::response(self::HOST, 15, [])]);
        $transport->script(['udp' => FakeDnsTransport::response(self::HOST, 16, [
            ['type' => 16, 'rdata' => self::txt('v=spf1 ip4:203.0.113.0/24 -all')],
            ['type' => 16, 'rdata' => self::txt('v=spf1 include:_spf.example.net -all')],
        ])]);

        $result = $this->probe($transport)->probe($this->target(), new ProbeOptions(timeoutSeconds: 2));

        self::assertTrue($result->payload['spf']['multiple']);
        self::assertSame('v=spf1 ip4:203.0.113.0/24 -all', $result->payload['spf']['record'], 'first record parsed');
        $highs = $this->findingsById($result, 'spf_multiple');
        self::assertCount(1, $highs);
        self::assertSame('high', $highs[0]['severity']);
    }

    public function test_dmarc_p_none_is_a_warning(): void
    {
        $transport = new FakeDnsTransport();
        $transport->script(['udp' => FakeDnsTransport::response(self::HOST, 15, [])]);
        $transport->script(['udp' => FakeDnsTransport::response(self::HOST, 16, [
            ['type' => 16, 'rdata' => self::txt('v=spf1 -all')],
        ])]);
        $transport->script(['udp' => FakeDnsTransport::response('_dmarc.'.self::HOST, 16, [
            ['type' => 16, 'rdata' => self::txt('v=DMARC1; p=none')],
        ])]);

        $result = $this->probe($transport)->probe($this->target(), new ProbeOptions(timeoutSeconds: 2));

        self::assertSame('none', $result->payload['dmarc']['policy']);
        $warns = $this->findingsById($result, 'dmarc_none_policy');
        self::assertCount(1, $warns);
        self::assertSame('warn', $warns[0]['severity']);
    }

    public function test_mx_ip_literal_is_a_high_finding(): void
    {
        $transport = new FakeDnsTransport();
        $transport->script(['udp' => FakeDnsTransport::response(self::HOST, 15, [
            ['type' => 15, 'rdata' => pack('n', 5).FakeDnsTransport::name('192.0.2.1')],
        ])]);

        $result = $this->probe($transport)->probe($this->target(), new ProbeOptions(timeoutSeconds: 2));

        self::assertTrue($result->payload['mx'][0]['ip_literal']);
        $highs = $this->findingsById($result, 'mx_ip_literal');
        self::assertCount(1, $highs);
        self::assertSame('high', $highs[0]['severity']);
    }

    public function test_dkim_selector_hit_is_reported(): void
    {
        $transport = new FakeDnsTransport();
        $transport->script(['udp' => FakeDnsTransport::response(self::HOST, 15, [])]);
        $transport->script(['udp' => FakeDnsTransport::response(self::HOST, 16, [])]);
        $transport->script(['udp' => FakeDnsTransport::response('_dmarc.'.self::HOST, 16, [])]);
        $transport->script(['udp' => FakeDnsTransport::response('_mta-sts.'.self::HOST, 16, [])]);
        $transport->script(['udp' => FakeDnsTransport::response('_smtp._tls.'.self::HOST, 16, [])]);
        // No MX → no CNAME/A sanity queries; selectors mail/default miss, google answers.
        $transport->script(['udp' => FakeDnsTransport::response('mail._domainkey.'.self::HOST, 16, [])]);
        $transport->script(['udp' => FakeDnsTransport::response('default._domainkey.'.self::HOST, 16, [])]);
        $transport->script(['udp' => FakeDnsTransport::response('google._domainkey.'.self::HOST, 16, [
            ['type' => 16, 'rdata' => self::txt('v=DKIM1; k=rsa; p=MIGfMA0GCS')],
        ])]);

        $result = $this->probe($transport)->probe($this->target(), new ProbeOptions(timeoutSeconds: 2));

        self::assertSame(['google'], $result->payload['dkim']);
        self::assertSame(12, count($transport->udpQueries), 'single hit → remaining candidates still probed');
    }

    public function test_absent_records_never_throw_and_land_as_findings(): void
    {
        $probe = $this->probe(new FakeDnsTransport());
        $result = $probe->probe($this->target(), new ProbeOptions(timeoutSeconds: 2));

        self::assertSame(['192.0.2.53'], $result->degradedSources);
        self::assertNull($result->payload['spf']);
        self::assertTrue($result->payload['dmarc']['missing']);
        self::assertContains('spf_missing', array_column($result->payload['findings'], 'id'));
        self::assertContains('dmarc_missing', array_column($result->payload['findings'], 'id'));
        self::assertContains('dkim_absent', array_column($result->payload['findings'], 'id'));
    }

    public function test_smtp_seam_runs_against_primary_mx(): void
    {
        $transport = new FakeDnsTransport();
        $transport->script(['udp' => FakeDnsTransport::response(self::HOST, 15, [
            ['type' => 15, 'rdata' => pack('n', 10).FakeDnsTransport::name('mail.'.self::HOST)],
        ])]);

        $askedHosts = [];
        $probe = new MailAuditProbe(
            dns: new DnsClient($transport),
            resolvers: ['192.0.2.53'],
            timeoutSeconds: 2,
            smtpCheck: function (string $mxHost) use (&$askedHosts): array {
                $askedHosts[] = $mxHost;

                return ['reachable' => true, 'starttls' => false, 'cert_days_left' => null, 'error' => ''];
            },
        );
        $result = $probe->probe($this->target(), new ProbeOptions(timeoutSeconds: 2));

        self::assertSame(['mail.example.com'], $askedHosts);
        self::assertTrue($result->payload['smtp']['reachable']);
        self::assertFalse($result->payload['smtp']['starttls']);
        $highs = $this->findingsById($result, 'starttls_missing');
        self::assertCount(1, $highs);
        self::assertSame('high', $highs[0]['severity']);
    }

    public function test_result_json_round_trip_is_lossless(): void
    {
        $transport = new FakeDnsTransport();
        $transport->script(['udp' => FakeDnsTransport::response(self::HOST, 15, [
            ['type' => 15, 'rdata' => pack('n', 10).FakeDnsTransport::name('mail.'.self::HOST)],
        ])]);

        $original = $this->probe($transport)->probe($this->target(), new ProbeOptions(timeoutSeconds: 2));
        $restored = ProbeResult::fromArray(
            json_decode(json_encode($original->toArray(), JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR),
        );

        self::assertSame($original->toArray(), $restored->toArray(), 'cache-purity rule: state-only DTO');
    }

    public function test_parser_parse_spf_edge_cases(): void
    {
        $plain = MailRecordsParser::parseSpf('v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 -all');
        self::assertSame(0, $plain['lookups'], 'ip4/ip6/all consume no DNS lookups');

        $full = MailRecordsParser::parseSpf(
            'v=spf1 include:_x.example a mx/24 ptr exists:x.example redirect=target.example',
        );
        self::assertSame(6, $full['lookups'], 'include/a/mx/ptr/exists/redirect each consume one lookup');
        self::assertSame('target.example', $full['redirect']);
        self::assertSame([], $full['errors']);

        $qualified = MailRecordsParser::parseSpf('v=spf1 ~include:_x.example -all');
        self::assertSame('~include:_x.example', $qualified['mechanisms'][0], 'qualifier preserved');

        $wrongVersion = MailRecordsParser::parseSpf('spf2.0/mfrom,example.com +all');
        self::assertNotSame([], $wrongVersion['errors']);

        $duplicateRedirect = MailRecordsParser::parseSpf('v=spf1 redirect=a.example redirect=b.example');
        self::assertSame(2, $duplicateRedirect['lookups']);
        self::assertCount(1, $duplicateRedirect['errors'], 'duplicate redirect flagged once');

        $unknown = MailRecordsParser::parseSpf('v=spf1 exp=explain.example bogusmechanism -all');
        self::assertSame([], array_filter($unknown['errors'], static fn (string $e): bool => str_contains($e, 'exp')), 'unknown modifier ignored');
        self::assertCount(1, $unknown['errors'], 'unknown mechanism is a syntax error');
    }

    public function test_parser_grade_dmarc_edge_cases(): void
    {
        $absent = MailRecordsParser::gradeDmarc(null);
        self::assertNull($absent['policy']);
        self::assertSame([], $absent['errors']);

        $strict = MailRecordsParser::gradeDmarc('v=DMARC1; p=reject; pct=30; rua=mailto:r@agg.example');
        self::assertSame('reject', $strict['policy']);
        self::assertTrue($strict['rua']);
        self::assertSame(30, $strict['pct']);

        $noPolicy = MailRecordsParser::gradeDmarc('v=DMARC1; rua=mailto:r@agg.example');
        self::assertNull($noPolicy['policy']);
        self::assertCount(1, $noPolicy['errors']);

        $badPolicy = MailRecordsParser::gradeDmarc('v=DMARC1; p=bogus');
        self::assertNull($badPolicy['policy']);
        self::assertCount(1, $badPolicy['errors']);

        $badPct = MailRecordsParser::gradeDmarc('v=DMARC1; p=quarantine; pct=150');
        self::assertNull($badPct['pct']);
        self::assertCount(1, $badPct['errors']);

        $notDmarc = MailRecordsParser::gradeDmarc('v=spf1 -all');
        self::assertNull($notDmarc['policy']);
        self::assertNotSame([], $notDmarc['errors']);
    }

    // ---- helpers ----

    private function probe(FakeDnsTransport $transport): MailAuditProbe
    {
        return new MailAuditProbe(new DnsClient($transport), ['192.0.2.53'], 2);
    }

    private static function target(): NetTarget
    {
        return new NetTarget(
            rawInput: self::HOST,
            host: self::HOST,
            ips: ['93.184.216.34'],
            isDomain: true,
            isIp: false,
            verdict: GuardVerdict::allow(),
        );
    }

    /** Single-string TXT rdata (length-prefix ≤255 bytes guaranteed by caller). */
    private static function txt(string $value): string
    {
        return chr(strlen($value)).$value;
    }

    /** Splits long records into multiple length-prefixed strings like real zones do. */
    private static function txtChunked(string $value): string
    {
        $wire = '';
        foreach (str_split($value, 255) as $chunk) {
            $wire .= chr(strlen($chunk)).$chunk;
        }

        return $wire;
    }

    /** @return list<array{severity: string, id: string, detail: string}> */
    private static function findingsWithSeverity(ProbeResult $result, string $severity): array
    {
        return array_values(array_filter(
            (array) ($result->payload['findings'] ?? []),
            static fn (array $f): bool => $f['severity'] === $severity,
        ));
    }

    /** @return list<array{severity: string, id: string, detail: string}> */
    private static function findingsById(ProbeResult $result, string $id): array
    {
        return array_values(array_filter(
            (array) ($result->payload['findings'] ?? []),
            static fn (array $f): bool => $f['id'] === $id,
        ));
    }
}
