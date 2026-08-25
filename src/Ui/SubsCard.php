<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;
use BAGArt\TelegramBotNettools\Results\ProbeResult;

/**
 * Pure /subs card per the §3.3 mockup: wildcard verdict, per-source counts,
 * monospace resolved table, suspected-takeover group, degraded warnings.
 * The ≤3800-char contract is enforced here by dropping resolved rows from
 * the tail (never mid-row) — the "Showing X of Y" line stays honest.
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class SubsCard
{
    /** Rendering slack for markup tags, title and footer wrappers. */
    private const int MARKUP_SLACK = 160;

    private const int NAME_COLUMN_WIDTH = 32;

    public static function render(ProbeResult $result, int $chatId, int $now, string $targetHost): array
    {
        unset($chatId, $now);

        $esc = HtmlRenderer::esc(...);
        $payload = $result->payload;
        $resolved = self::resolvedCandidates($payload);
        $allNames = count((array) ($payload['resolved'] ?? [])) + count((array) ($payload['ct_only'] ?? []));

        [$rows, $shown] = self::fitRows($resolved, self::fixedBudgetChars($payload));

        $header = [
            self::wildcardLine($payload),
            self::sourcesLine($payload),
        ];

        $sections = [
            new Section('', $header),
            new Section('', self::summaryLines($rows, $allNames, $shown), monospace: true),
            ...self::suspectSections($payload),
        ];

        foreach (array_values(array_filter(array_map(strval(...), $result->degradedSources))) as $source) {
            $sections[] = new Section('', ['⚠️ Source '.$esc($source).' unavailable — partial results']);
        }

        $footer = new Footer();
        foreach ((array) ($payload['sources'] ?? []) as $source) {
            if (is_string($source) && $source !== '') {
                $footer->add($source, $result->latencyMs);
            }
        }
        if ($footer->isEmpty()) {
            $footer->add('local', $result->latencyMs);
        }

        return [
            'text' => (new HtmlRenderer())->render('SUBDOMAINS · '.$targetHost, $sections, $footer),
            'keyboard' => [],
        ];
    }

    /**
     * Display-worthy rows only (an address or a CNAME present), as raw
     * [name, rendered target] pairs; escaping happens here.
     *
     * @return list<array{0: string, 1: string}>
     */
    private static function resolvedCandidates(array $payload): array
    {
        $esc = HtmlRenderer::esc(...);
        $candidates = [];

        foreach ((array) ($payload['resolved'] ?? []) as $row) {
            $row = (array) $row;
            $name = is_string($row['name'] ?? null) ? $row['name'] : '';
            $ips = array_values(array_filter(array_map(strval(...), (array) ($row['ips'] ?? []))));
            $cname = is_string($row['cname'] ?? null) && $row['cname'] !== '' ? $row['cname'] : null;

            if ($name === '' || ($ips === [] && $cname === null)) {
                continue;
            }

            $target = $cname !== null
                ? '→ CNAME '.$esc($cname)
                : implode(', ', array_map($esc, $ips));
            if ($cname === null && self::hasInternalIp($ips)) {
                $target .= '  ⚠ internal-looking';
            }

            $candidates[] = [$esc($name), $target];
        }

        return $candidates;
    }

    /**
     * Whole-rows-only fit into the remaining char budget.
     *
     * @param  list<array{0: string, 1: string}>  $candidates
     * @return array{0: list<string>, 1: int} rendered lines + shown count
     */
    private static function fitRows(array $candidates, int $budget): array
    {
        $width = self::NAME_COLUMN_WIDTH;
        foreach ($candidates as [$name]) {
            $width = max($width, mb_strlen($name) + 2);
        }

        $lines = [];
        $used = 0;
        foreach ($candidates as $candidate) {
            $line = str_pad($candidate[0], $width).'  '.$candidate[1];

            if ($used + mb_strlen($line) + 1 > $budget) {
                break;
            }

            $lines[] = $line;
            $used += mb_strlen($line) + 1;
        }

        return [$lines, count($lines)];
    }

    /** Char spend of everything that is not a resolved row. */
    private static function fixedBudgetChars(array $payload): int
    {
        $suspects = count((array) ($payload['suspect_takeover'] ?? []));
        $degraded = count((array) ($payload['degraded'] ?? []));
        $wordlistPart = (int) ($payload['counts']['brute_queried'] ?? 0) > 0 ? 40 : 0;

        // title + header lines + summary scaffolding + suspects + degraded + slack
        return 260 + $suspects * 60 + $degraded * 70 + $wordlistPart + self::MARKUP_SLACK;
    }

    /** @param list<string> $rows @return list<string> */
    private static function summaryLines(array $rows, int $allNames, int $shown): array
    {
        if ($rows === []) {
            return ['No resolving subdomains found.', '', 'Showing 0 of '.$allNames];
        }

        return [
            'Resolved ('.$shown.'):',
            ...$rows,
            '',
            'Showing '.$shown.' of '.$allNames,
        ];
    }

    /** @param array<string, mixed> $payload */
    private static function wildcardLine(array $payload): string
    {
        return ($payload['wildcard'] ?? false) === true
            ? 'Wildcard: yes ⚠️ brute-force rows unreliable'
            : 'Wildcard: no ✅';
    }

    /** @param array<string, mixed> $payload */
    private static function sourcesLine(array $payload): string
    {
        $parts = [];
        foreach ((array) ($payload['source_counts'] ?? []) as $name => $count) {
            $parts[] = HtmlRenderer::esc((string) $name).' ('.(int) $count.')';
        }

        $queried = (int) ($payload['counts']['brute_queried'] ?? 0);
        if ($queried > 0) {
            $parts[] = 'wordlist ('.(int) ($payload['counts']['brute_resolved'] ?? 0).' resolved / '.$queried.')';
        }

        return $parts === [] ? 'Sources: none' : 'Sources: '.implode(' · ', $parts);
    }

    /**
     * ❌ group for DNS-only takeover hints — wording always "suspected".
     *
     * @return list<Section>
     */
    private static function suspectSections(array $payload): array
    {
        $entries = [];
        foreach ((array) ($payload['suspect_takeover'] ?? []) as $entry) {
            $entry = (array) $entry;
            $name = is_string($entry['name'] ?? null) ? $entry['name'] : '';
            $provider = is_string($entry['provider'] ?? null) ? $entry['provider'] : '';

            if ($name !== '' && $provider !== '') {
                $entries[] = HtmlRenderer::esc($name).' → '.HtmlRenderer::esc($provider);
            }
        }

        if ($entries === []) {
            return [];
        }

        return [new Section('', [
            '❌ suspected dangling CNAME — verify before registering:',
            ...$entries,
        ])];
    }

    /**
     * RFC1918 check by simple octet comparison (v4 only).
     *
     * @param  list<string>  $ips
     */
    private static function hasInternalIp(array $ips): bool
    {
        foreach ($ips as $ip) {
            if (! preg_match('/^(\d+)\.(\d+)\.\d+\.\d+$/', $ip, $m)) {
                continue;
            }
            $first = (int) $m[1];
            $second = (int) $m[2];
            if ($first === 10 || ($first === 172 && $second >= 16 && $second <= 31) || ($first === 192 && $second === 168)) {
                return true;
            }
        }

        return false;
    }
}
