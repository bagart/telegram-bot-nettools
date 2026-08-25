<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;

/**
 * Pure /report card (RFC §4.4 / Appendix C): section status grid, reco
 * score headline, degraded/failed lines; section nav buttons live in the
 * command, not here.
 */
final class ReportCard
{
    private const array GLYPHS = ['✅', '⚠️', '❌'];

    /**
     * @param  array<string, \BAGArt\TelegramBotNettools\Results\ProbeResult>  $results
     * @param  list<string>  $degraded  "probe:source" entries
     * @param  list<string>  $failed    "probe:label" entries
     * @param  array{score:int, grade:string, passed:int, failed:int, findings:list<array>}|null  $verdict
     */
    public static function render(
        string $hostLabel,
        int $totalMs,
        array $results,
        array $degraded,
        array $failed,
        ?array $verdict,
        bool $cachedOnly = false,
    ): array {
        $esc = HtmlRenderer::esc(...);
        $lines = [];

        if ($verdict !== null) {
            $lines[] = "Score: {$verdict['score']}/100 — grade ".(string) $verdict['grade'];
            $lines[] = '';
        }

        foreach (array_keys($results) as $name) {
            $result = $results[$name];
            $findingCount = is_countable($result->payload['findings'] ?? null) ? count((array) $result->payload['findings']) : 0;
            $glyph = match (true) {
                $findingCount > 0 => self::worstGlyph($result),
                default => '✅',
            };
            $age = '';

            $lines[] = "{$glyph} ".str_pad($name, 8)."(".(int) $result->latencyMs." ms{$age})";
        }

        foreach ($failed as $entry) {
            $lines[] = '⚠️ '.str_pad((string) strtok($entry, ':'), 8).'skipped ('.(string) substr($entry, (int) strrpos(':'.$entry, ':') + 1).')';
        }

        $sections = [new Section('', $lines, monospace: true)];

        if ($verdict !== null && $verdict['findings'] !== []) {
            $top = array_slice(array_filter($verdict['findings'], static fn ($f): bool => (string) $f['severity'] === 'high'), 0, 5);
            $topLines = [];
            foreach ($top as $finding) {
                $topLines[] = '• ❌ '.$esc((string) $finding['detail']);
            }
            if ($topLines !== []) {
                $sections[] = new Section('Top issues', $topLines);
            }
        }

        $warns = [...array_map(static fn (string $d): string => '⚠️ source unavailable: '.$esc($d), $degraded)];
        if ($verdict === null) {
            $warns[] = 'ℹ️ run /reco for graded recommendations';
        }
        if ($warns !== []) {
            $sections[] = new Section('', $warns);
        }

        $footer = new Footer();
        $footer->add(count($results).' probes', $totalMs);

        return [
            'text' => (new HtmlRenderer())->render('REPORT · '.$esc($hostLabel), $sections, $footer),
            'keyboard' => [],
        ];
    }

    private static function worstGlyph(\BAGArt\TelegramBotNettools\Results\ProbeResult $result): string
    {
        $worst = 'info';
        foreach ((array) ($result->payload['findings'] ?? []) as $finding) {
            if ((string) $finding['severity'] === 'high') {
                return '❌';
            }
            if ((string) $finding['severity'] === 'warn') {
                $worst = 'warn';
            }
        }

        return $worst === 'warn' ? '⚠️' : '✅';
    }
}
