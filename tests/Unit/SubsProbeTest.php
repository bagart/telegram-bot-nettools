<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Probes\SubsProbe;
use BAGArt\TelegramBotNettools\Results\GuardVerdict;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Sources\CtLogSource;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Tests\Support\FakeDnsTransport;
use BAGArt\TelegramBotNettools\Tests\Support\FakeHttpSource;
use BAGArt\TelegramBotNettools\Ui\SubsCard;
use PHPUnit\Framework\TestCase;

/**
 * SubsProbe fixture tests (RFC §7.6): CT parsing sans wildcards, wildcard-
 * zone detection flagging brute rows, brute opt-in gating, certspotter
 * fallback, takeover fingerprints, degraded sources, JSON round-trip and
 * the ≤3800-char card contract.
 */
final class SubsProbeTest extends TestCase
{
    private const string CRTSH_URL = 'https://crt.sh/?q=%25.example.com&output=json';

    private const string CERTSPOTTER_URL =
        'https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names';

    private const string RESOLVER = '192.0.2.53';

    private static function target(string $host = 'example.com'): NetTarget
    {
        return new NetTarget(
            rawInput: $host,
            host: $host,
            ips: ['93.184.216.34'],
            isDomain: true,
            isIp: false,
            verdict: GuardVerdict::allow(),
        );
    }

    private static function aRecordResponse(string $questionName, string $ip): array
    {
        return ['udp' => FakeDnsTransport::response($questionName, 1, [
            ['type' => 1, 'ttl' => 300, 'rdata' => inet_pton($ip)],
        ])];
    }

    private static function probe(FakeHttpSource $http, FakeDnsTransport $transport, array $options = []): SubsProbe
    {
        return new SubsProbe(
            new CtLogSource($http),
            new DnsClient($transport),
            [self::RESOLVER],
            ...$options,
        );
    }

    private static function runProbe(SubsProbe $probe, ?ProbeOptions $options = null): ProbeResult
    {
        return $probe->probe(self::target(), $options ?? new ProbeOptions(timeoutSeconds: 5));
    }

    public function test_crtsh_fixture_is_parsed_into_unique_names_without_wildcards(): void
    {
        $http = new FakeHttpSource([
            self::CRTSH_URL => [
                ['name_value' => "www.example.com\n*.example.com\nmail.example.com"],
                ['name_value' => 'WWW.Example.COM'],
                ['name_value' => '*.dev.example.com'],
                ['name_value' => 'api.example.com'],
                ['name_value' => 'unrelated.invalid'],
            ],
        ]);
        $result = self::runProbe(self::probe($http, new FakeDnsTransport()));

        $names = array_column($result->payload['resolved'], 'name');

        self::assertSame(
            ['api.example.com', 'dev.example.com', 'example.com', 'mail.example.com', 'www.example.com'],
            $names,
            'lowercased, wildcard-stripped, deduped, suffix-filtered',
        );
        self::assertSame(5, $result->payload['counts']['ct']);
        self::assertSame(['crt.sh'], $result->payload['sources']);
        self::assertSame([], $result->degradedSources);
        self::assertSame([], $result->payload['ct_only']);
        self::assertFalse($result->payload['truncated']);
        self::assertFalse($result->payload['wildcard']);
        self::assertSame([self::CRTSH_URL], $http->requestedUrls, '5 results ⇒ no certspotter fallback');
    }

    public function test_wildcard_zone_flags_brute_rows_as_wildcard_suspect(): void
    {
        $transport = new FakeDnsTransport();
        // random-label probes hit answers (wildcard zone), brute labels too
        $transport->script(self::aRecordResponse('random-a.example.com', '203.0.113.99'));
        $transport->script(self::aRecordResponse('random-b.example.com', '203.0.113.99'));
        $transport->script(self::aRecordResponse('beta.example.com', '203.0.113.50'));
        $transport->script(self::aRecordResponse('alpha.example.com', '203.0.113.51'));

        $result = self::runProbe(
            self::probe(new FakeHttpSource(), $transport, ['wordlistOverride' => ['beta', 'alpha']]),
            new ProbeOptions(flags: [SubsProbe::FLAG_BRUTE => true], timeoutSeconds: 2),
        );

        self::assertTrue($result->payload['wildcard']);
        self::assertSame(2, $result->payload['counts']['brute_resolved']);

        foreach ($result->payload['resolved'] as $row) {
            self::assertSame('wildcard-zone', $row['suspect'], 'brute row must be wildcard-suspect');
        }
        self::assertSame([], $result->payload['suspect_takeover']);
        self::assertSame(['crt.sh', 'certspotter'], $result->degradedSources);
    }

    public function test_brute_is_off_by_default_and_skips_wordlist_queries(): void
    {
        $transport = new FakeDnsTransport();
        $labels = ['zz-bruteprobe'];

        $result = self::runProbe(self::probe(new FakeHttpSource(), $transport, ['wordlistOverride' => $labels]));

        self::assertSame(0, $result->payload['counts']['brute_queried']);
        self::assertSame(0, $result->payload['counts']['brute_resolved']);
        self::assertCount(2, $transport->udpQueries, 'only the two wildcard-detection probes ran');
        self::assertStringNotContainsString('bruteprobe', implode('', $transport->udpQueries));
    }

    public function test_brute_opt_in_resolves_override_wordlist_subset(): void
    {
        $transport = new FakeDnsTransport();
        $transport->script(['udp' => null]); // wildcard label 1
        $transport->script(['udp' => null]); // wildcard label 2
        $transport->script(['udp' => null]); // gamma
        $transport->script(['udp' => null]); // beta
        $transport->script(self::aRecordResponse('alpha.example.com', '203.0.113.10'));

        $result = self::runProbe(
            self::probe(new FakeHttpSource(), $transport, ['wordlistOverride' => ['gamma', 'beta', 'alpha', 'alpha']]),
            new ProbeOptions(flags: [SubsProbe::FLAG_BRUTE => true], timeoutSeconds: 2),
        );

        self::assertSame(3, $result->payload['counts']['brute_queried'], 'duplicates collapse');
        self::assertSame(1, $result->payload['counts']['brute_resolved']);

        $rows = array_column($result->payload['resolved'], null, 'name');
        self::assertSame(['203.0.113.10'], $rows['alpha.example.com']['ips']);
        self::assertFalse($result->payload['wildcard']);
        self::assertArrayNotHasKey('beta.example.com', $rows);
    }

    public function test_certspotter_fallback_triggers_when_crtsh_is_null(): void
    {
        $http = new FakeHttpSource([
            self::CERTSPOTTER_URL => [
                ['dns_names' => ['alt.example.com', 'EXAMPLE.COM']],
                ['dns_names' => ['*.alt.example.com']],
            ],
        ]);

        $result = self::runProbe(self::probe($http, new FakeDnsTransport()));

        self::assertContains(self::CERTSPOTTER_URL, $http->requestedUrls);
        self::assertSame(['certspotter'], $result->payload['sources']);
        self::assertSame(['crt.sh'], $result->degradedSources);

        $names = array_column($result->payload['resolved'], 'name');
        self::assertSame(['alt.example.com', 'example.com'], $names);
        self::assertSame(2, $result->payload['counts']['ct']);
    }

    public function test_takeover_fingerprint_marks_row_suspect(): void
    {
        $http = new FakeHttpSource([
            self::CRTSH_URL => [['name_value' => 'dangling.example.com']],
        ]);
        $transport = new FakeDnsTransport();
        $transport->script(['udp' => null]);
        $transport->script(['udp' => null]);
        $transport->script(['udp' => FakeDnsTransport::response('dangling.example.com', 1, [
            ['type' => 5, 'ttl' => 300, 'rdata' => FakeDnsTransport::name('old-bucket.s3.amazonaws.com')],
        ])]);

        $result = self::runProbe(self::probe($http, $transport));

        $row = $result->payload['resolved'][0];
        self::assertSame('old-bucket.s3.amazonaws.com', $row['cname']);
        self::assertSame('s3.amazonaws.com', $row['suspect']);
        self::assertSame(
            [['name' => 'dangling.example.com', 'provider' => 's3.amazonaws.com']],
            $result->payload['suspect_takeover'],
        );
    }

    public function test_both_ct_sources_degraded_still_return_a_full_payload(): void
    {
        $result = self::runProbe(self::probe(new FakeHttpSource(), new FakeDnsTransport()));

        self::assertSame(['crt.sh', 'certspotter'], $result->degradedSources);
        foreach (['host', 'wildcard', 'resolved', 'ct_only', 'counts', 'sources', 'suspect_takeover', 'truncated'] as $key) {
            self::assertArrayHasKey($key, $result->payload);
        }
        self::assertSame(0, $result->payload['counts']['ct']);
        self::assertSame([], $result->payload['resolved']);
        self::assertSame('subs', $result->probe);
        self::assertSame(43200, self::probe(new FakeHttpSource(), new FakeDnsTransport())->ttlSeconds());
    }

    public function test_result_json_round_trip_is_lossless(): void
    {
        $http = new FakeHttpSource([
            self::CRTSH_URL => [['name_value' => 'dangling.example.com']],
        ]);
        $transport = new FakeDnsTransport();
        $transport->script(['udp' => null]);
        $transport->script(['udp' => null]);
        $transport->script(['udp' => FakeDnsTransport::response('dangling.example.com', 1, [
            ['type' => 5, 'ttl' => 300, 'rdata' => FakeDnsTransport::name('site.github.io')],
        ])]);

        $original = self::runProbe(self::probe($http, $transport));
        $restored = ProbeResult::fromArray(
            json_decode(json_encode($original->toArray(), JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR),
        );

        self::assertSame($original->toArray(), $restored->toArray(), 'cache-purity rule: state-only DTO');
    }

    public function test_card_stays_within_limit_and_keeps_title(): void
    {
        $labels = [];
        for ($i = 0; $i < 240; $i++) {
            $labels[] = sprintf('w%03d', $i);
        }

        $transport = new FakeDnsTransport();
        $transport->script(['udp' => null]);
        $transport->script(['udp' => null]);
        foreach ($labels as $i => $label) {
            $transport->script(self::aRecordResponse($label.'.example.com', '198.51.100.'.($i % 254 + 1)));
        }

        $result = self::runProbe(
            self::probe(new FakeHttpSource(), $transport, ['wordlistOverride' => $labels]),
            new ProbeOptions(flags: [SubsProbe::FLAG_BRUTE => true], timeoutSeconds: 2),
        );

        self::assertTrue($result->payload['truncated'], 'names beyond maxShow/query cap ⇒ ct_only tail');
        self::assertCount(130, $result->payload['ct_only'], '220-query cap ≈ 110 names × A+AAAA');
        self::assertCount(110, $result->payload['resolved']);

        $card = SubsCard::render($result, 42, time(), 'example.com');

        self::assertLessThanOrEqual(3800, mb_strlen($card['text']));
        self::assertStringContainsString('SUBDOMAINS · example.com', $card['text']);
        self::assertStringContainsString('Showing ', $card['text']);
        self::assertSame([], $card['keyboard']);
    }
}
