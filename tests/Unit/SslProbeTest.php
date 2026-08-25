<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Probes\SslProbe;
use BAGArt\TelegramBotNettools\Results\GuardVerdict;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\SslCard;
use PHPUnit\Framework\TestCase;

/**
 * SslProbe fixture tests (RFC §7.7): deterministic findings matrix, wildcard
 * hostname semantics, no-TLS distinct result, JSON round-trip, card budget.
 */
final class SslProbeTest extends TestCase
{
    public function test_good_certificate_produces_no_findings_and_renders_card(): void
    {
        $result = $this->probe()->probe(self::target(), new ProbeOptions(timeoutSeconds: 5));

        self::assertTrue($result->payload['has_tls']);
        self::assertNull($result->payload['error']);
        self::assertSame([], $result->payload['findings']);
        self::assertSame([], $result->degradedSources);
        self::assertSame('TLS1.3', $result->payload['protocol']);
        self::assertSame(['h2'], $result->payload['alpn']);
        self::assertSame(3, $result->payload['chain_count']);
        foreach (['host', 'has_tls', 'error', 'protocol', 'alpn', 'cert', 'chain_count', 'self_signed', 'ocsp_stapled', 'offered_protocols', 'findings'] as $key) {
            self::assertArrayHasKey($key, $result->payload);
        }
        /** @var array<string, mixed> $cert */
        $cert = $result->payload['cert'];
        self::assertSame('example.org', $cert['subject_cn']);
        self::assertThat($cert['days_left'], self::logicalAnd(
            self::greaterThanOrEqual(199),
            self::lessThanOrEqual(200),
        ));

        $card = SslCard::render($result, 42, time(), 'example.org');
        self::assertStringContainsString('SSL ·', $card['text']);
        self::assertSame([], $card['keyboard']);
    }

    public function test_expired_certificate_is_high_finding(): void
    {
        $now = time();
        $expired = $this->probe(['cert' => [
            'valid_from' => $now - 400 * 86400,
            'valid_to' => $now - 10 * 86400,
        ]])->probe(self::target(), new ProbeOptions(timeoutSeconds: 5));

        self::assertSame([['severity' => 'high', 'id' => 'expired']], array_map(
            static fn (array $finding): array => ['severity' => $finding['severity'], 'id' => $finding['id']],
            $expired->payload['findings'],
        ));

        $notYet = $this->probe(['cert' => [
            'valid_from' => $now + 5 * 86400,
            'valid_to' => $now + 100 * 86400,
        ]])->probe(self::target(), new ProbeOptions(timeoutSeconds: 5));

        self::assertContains('not_valid_yet', array_column($notYet->payload['findings'], 'id'));
    }

    public function test_legacy_protocol_is_high_finding_and_card_marks_it(): void
    {
        $offered = $this->probe(['offered_protocols' => ['TLS1.0', 'TLS1.2', 'TLS1.3']])
            ->probe(self::target(), new ProbeOptions(timeoutSeconds: 5));
        $findings = array_combine(
            array_column($offered->payload['findings'], 'id'),
            array_column($offered->payload['findings'], 'severity'),
        );

        self::assertSame('high', $findings['legacy_protocol']);

        $negotiatedOnly = $this->probe(['protocol' => 'TLS1.1', 'offered_protocols' => []])
            ->probe(self::target(), new ProbeOptions(timeoutSeconds: 5));

        self::assertContains('legacy_protocol', array_column($negotiatedOnly->payload['findings'], 'id'));

        $card = SslCard::render($offered, 42, time(), 'example.org');
        self::assertStringContainsString('❌', $card['text']);
    }

    public function test_weak_rsa_key_is_high_finding(): void
    {
        $result = $this->probe(['cert' => ['key_bits' => 1024]])
            ->probe(self::target(), new ProbeOptions(timeoutSeconds: 5));

        $findings = array_combine(
            array_column($result->payload['findings'], 'id'),
            array_column($result->payload['findings'], 'severity'),
        );

        self::assertSame('high', $findings['weak_key']);
    }

    public function test_self_signed_certificate_is_high_finding(): void
    {
        $result = $this->probe(['chain_count' => 1, 'self_signed' => true])
            ->probe(self::target(), new ProbeOptions(timeoutSeconds: 5));

        $findings = array_combine(
            array_column($result->payload['findings'], 'id'),
            array_column($result->payload['findings'], 'severity'),
        );

        self::assertSame('high', $findings['self_signed']);
        self::assertSame('warn', $findings['incomplete_chain'], 'single-certificate chain is flagged as incomplete too');
    }

    public function test_wildcard_san_matches_exactly_one_label(): void
    {
        $cases = [
            'a.example.com' => false,
            'a.b.example.com' => true,
            'example.com' => true,
        ];

        foreach ($cases as $host => $expectMismatch) {
            $result = $this->probe(['cert' => ['subject_cn' => '*.example.com', 'san' => ['*.example.com']]])
                ->probe(self::target($host), new ProbeOptions(timeoutSeconds: 5));

            $ids = array_column($result->payload['findings'], 'id');

            if ($expectMismatch) {
                self::assertContains('hostname_mismatch', $ids, "{$host} must NOT match *.example.com");
            } else {
                self::assertNotContains('hostname_mismatch', $ids, "{$host} must match *.example.com");
            }
        }
    }

    public function test_no_tls_is_distinct_result_not_an_error(): void
    {
        $noTlsInspection = [
            'host' => 'example.org',
            'has_tls' => false,
            'error' => 'refused',
        ];
        $refused = new SslProbe(static fn (string $host, int $port, float $timeoutSeconds): ?array => $noTlsInspection)
            ->probe(self::target(), new ProbeOptions(timeoutSeconds: 5));

        self::assertFalse($refused->payload['has_tls']);
        self::assertSame('refused', $refused->payload['error']);
        self::assertNull($refused->payload['protocol']);
        self::assertNull($refused->payload['cert']);
        self::assertSame([], $refused->payload['alpn']);
        self::assertSame([], $refused->payload['findings']);
        self::assertSame([], $refused->degradedSources);

        $nullSeam = new SslProbe(static fn (string $host, int $port, float $timeoutSeconds): ?array => null)
            ->probe(self::target(), new ProbeOptions(timeoutSeconds: 5));

        self::assertFalse($nullSeam->payload['has_tls']);
        self::assertSame('other', $nullSeam->payload['error']);

        $card = SslCard::render($refused, 42, time(), 'example.org');
        self::assertStringContainsString('No TLS service detected', $card['text']);
    }

    public function test_result_json_round_trip_is_lossless(): void
    {
        $original = $this->probe()->probe(self::target(), new ProbeOptions(timeoutSeconds: 5));
        $restored = ProbeResult::fromArray(
            json_decode(json_encode($original->toArray(), JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR),
        );

        self::assertSame($original->toArray(), $restored->toArray(), 'cache-purity rule: state-only DTO');
    }

    public function test_card_stays_within_char_budget(): void
    {
        $worstCase = $this->probe([
            'chain_count' => 1,
            'self_signed' => true,
            'offered_protocols' => ['TLS1.0', 'TLS1.1', 'TLS1.2', 'TLS1.3'],
            'cert' => [
                'valid_from' => time() - 500 * 86400,
                'valid_to' => time() + 10 * 86400,
                'key_bits' => 1024,
            ],
        ])->probe(self::target(), new ProbeOptions(timeoutSeconds: 5));

        $card = SslCard::render($worstCase, 42, time(), 'example.org');

        self::assertLessThan(3800, mb_strlen($card['text']));
        self::assertStringContainsString('• ', $card['text'], 'findings are rendered as bullets');
    }

    /**
     * Inspector stub returning the canonical good inspection with overrides
     * ('cert' key merges into the leaf-certificate fixture, rest is top-level).
     *
     * @param  array<string, mixed>  $overrides
     */
    private function probe(array $overrides = []): SslProbe
    {
        return new SslProbe(static fn (string $host, int $port, float $timeoutSeconds): ?array => self::inspection($overrides));
    }

    private static function target(string $host = 'example.org'): NetTarget
    {
        return new NetTarget(
            rawInput: $host,
            host: $host,
            ips: [$host],
            isDomain: true,
            isIp: false,
            verdict: GuardVerdict::allow(),
        );
    }

    /**
     * Canonical healthy inspection (RFC §7.7 payload contract); $overrides
     * entries under 'cert' merge into the leaf certificate, the rest replace
     * top-level inspection keys.
     *
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    private static function inspection(array $overrides = []): array
    {
        $now = time();

        $inspection = [
            'host' => 'example.org',
            'has_tls' => true,
            'error' => null,
            'protocol' => 'TLS1.3',
            'alpn' => ['h2'],
            'chain_count' => 3,
            'self_signed' => false,
            'ocsp_stapled' => false,
            'offered_protocols' => ['TLS1.2', 'TLS1.3'],
            'cert' => [
                'subject_cn' => 'example.org',
                'issuer_cn' => 'R3',
                'issuer_org' => "Let's Encrypt",
                'san' => ['example.org', 'www.example.org'],
                'valid_from' => $now - 100 * 86400,
                'valid_to' => $now + 200 * 86400,
                'sig_alg' => 'sha256WithRSAEncryption',
                'key_alg' => 'RSA',
                'key_bits' => 2048,
                'serial' => '04ABCD1234EF',
                'sha256_fp' => str_repeat('ab', 32),
            ],
        ];

        $certOverrides = (array) ($overrides['cert'] ?? []);
        unset($overrides['cert']);

        return [...$inspection, ...$overrides, 'cert' => array_merge($inspection['cert'], $certOverrides)];
    }
}
