<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;

/**
 * Pure /os card (RFC §7.10): candidates with confidence labels, honest
 * "insufficient signals" state — heuristics never asserted as fact.
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class OsCard
{
    public static function render(ProbeResult $result, int $chatId, int $now, string $targetHost): array
    {
        $esc = HtmlRenderer::esc(...);
        $p = $result->payload;

        if ((bool) ($p['insufficient'] ?? false)) {
            return [
                'text' => (new HtmlRenderer())->render(
                    'OS · '.$esc($targetHost),
                    [new Section('', ['🤷 Insufficient signals — host filtered probes or hides banners. This is a valid answer, not an error.'])],
                    (new Footer())->add('heuristic', $result->latencyMs),
                ),
                'keyboard' => [MenuBackRow::row($chatId)],
            ];
        }

        $lines = [];
        foreach ((array) ($p['candidates'] ?? []) as $candidate) {
            $icon = (string) $candidate['confidence'] === 'medium' ? '🟡' : '⚪';
            $lines[] = "{$icon} ".str_pad((string) $candidate['family'], 26).$esc((string) $candidate['confidence']);
            $lines[] = str_repeat(' ', 4).$esc((string) $candidate['detail']).'  ['.$esc((string) $candidate['source']).']';
        }

        $sections = [
            new Section('Candidates (low-confidence by design)', $lines, monospace: true),
            new Section('', ['ℹ️ Heuristic fingerprint only — raw-SYN stack matching is out of scope.']),
        ];

        return [
            'text' => (new HtmlRenderer())->render(
                'OS · '.$esc($targetHost),
                $sections,
                (new Footer())->add('heuristic', $result->latencyMs),
            ),
            'keyboard' => [MenuBackRow::row($chatId)],
        ];
    }
}
