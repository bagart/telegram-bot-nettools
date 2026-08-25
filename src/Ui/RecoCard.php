<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;

/**
 * Pure /reco scorecard (RFC §3.3 mockup): graded findings grouped HIGH /
 * WARN / INFO with fix hints, footer with rules-passed evidence line.
 */
final class RecoCard
{
    /**
     * @param  array{score:int, grade:string, passed:int, failed:int, findings:list<array{severity:string,id:string,detail:string,hint:string}>}  $verdict
     * @return array{text: string}
     */
    public static function render(array $verdict, string $hostLabel): array
    {
        $esc = HtmlRenderer::esc(...);
        $gradeIcon = match ((string) $verdict['grade']) {
            'A' => '🟢',
            'B' => '🟢',
            'C' => '🟡',
            default => '🔴',
        };

        $sections = [
            new Section('', ["{$gradeIcon} Score: {$verdict['score']}/100 — grade ".(string) $verdict['grade']]),
        ];

        foreach (['high' => 'HIGH', 'warn' => 'WARN', 'info' => 'INFO'] as $severity => $title) {
            $lines = [];
            foreach ($verdict['findings'] as $finding) {
                if ((string) $finding['severity'] !== $severity) {
                    continue;
                }

                $glyph = $severity === 'high' ? '❌' : ($severity === 'warn' ? '⚠️' : 'ℹ️');
                $lines[] = "• {$glyph} ".$esc((string) $finding['detail']);
                $lines[] = str_repeat(' ', 2).'↳ fix: '.$esc((string) $finding['hint']);
            }

            if ($lines !== []) {
                $sections[] = new Section($title, $lines);
            }
        }

        if ($verdict['findings'] === []) {
            $sections[] = new Section('', ['✅ No issues found by the current rule set.']);
        }

        $sections[] = new Section('', [
            "Rules passed: {$verdict['passed']} · failed: {$verdict['failed']} · evidence: <i>/report ".HtmlRenderer::esc($hostLabel).'</i>',
        ]);

        return ['text' => (new HtmlRenderer())->render('RECO · '.$esc($hostLabel), $sections, null)];
    }
}
