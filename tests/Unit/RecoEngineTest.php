<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Support\RecoEngine;
use PHPUnit\Framework\TestCase;

/**
 * Deterministic scorecard rules (RFC §8): deductions, grading, context
 * rules over raw DNS/whois payloads.
 */
final class RecoEngineTest extends TestCase
{
    private function makeResult(string $probe, array $payload, array $findings = []): ProbeResult
    {
        return new ProbeResult(probe: $probe, fetchedAt: 0, latencyMs: 0, degradedSources: [], payload: [...$payload, 'findings' => $findings]);
    }

    public function test_all_pass_scores_100_a(): void
    {
        $verdict = (new RecoEngine())->evaluate([
            'dns' => $this->makeResult('dns', ['records' => ['A' => ['1.2.3.4'], 'AAAA' => ['::1'], 'CAA' => '0 issue ca.example'], 'dnssec_ad' => true]),
            'whois' => $this->makeResult('whois', ['dnssec' => true]),
        ]);

        self::assertSame(100, $verdict['score']);
        self::assertSame('A', $verdict['grade']);
        self::assertSame([], $verdict['findings']);
    }

    public function test_context_rules_fire_for_sparse_dns(): void
    {
        $verdict = (new RecoEngine())->evaluate([
            'dns' => $this->makeResult('dns', ['records' => ['A' => ['1.2.3.4']]]),
            'whois' => $this->makeResult('whois', ['dnssec' => false]),
        ]);

        $ids = array_column($verdict['findings'], 'id');
        sort($ids);

        self::assertSame(['caa_absent', 'dnssec_absent', 'ipv6_absent'], $ids);
        // warn(5) + info(1) + warn(5) = 11 → 89 → B boundary check
        self::assertSame(89, $verdict['score']);
        self::assertSame('B', $verdict['grade']);
    }

    public function test_probe_findings_map_to_hints_and_grading(): void
    {
        $verdict = (new RecoEngine())->evaluate([
            'ssl' => $this->makeResult('ssl', [], [
                ['severity' => 'high', 'id' => 'expired', 'detail' => 'cert expired'],
                ['severity' => 'warn', 'id' => 'expiring', 'detail' => 'renew window'],
            ]),
            'mail' => $this->makeResult('mail', [], [
                ['severity' => 'high', 'id' => 'spf_missing', 'detail' => 'no SPF record'],
            ]),
        ]);

        self::assertSame(65, $verdict['score'], '100 -15 -15 -5 = 65');
        self::assertSame('C', $verdict['grade']);

        $hints = [];
        foreach ($verdict['findings'] as $finding) {
            $hints[$finding['id']] = $finding['hint'];
        }
        self::assertSame('renew immediately — the certificate has expired', $hints['expired']);
        self::assertStringContainsString('v=spf1', $hints['spf_missing']);

        // determinism: same input → byte-identical output
        $again = (new RecoEngine())->evaluate([
            'ssl' => $this->makeResult('ssl', [], [
                ['severity' => 'high', 'id' => 'expired', 'detail' => 'cert expired'],
                ['severity' => 'warn', 'id' => 'expiring', 'detail' => 'renew window'],
            ]),
            'mail' => $this->makeResult('mail', [], [
                ['severity' => 'high', 'id' => 'spf_missing', 'detail' => 'no SPF record'],
            ]),
        ]);
        self::assertSame($verdict, $again);
    }
}
