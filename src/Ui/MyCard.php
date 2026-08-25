<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Support\HumanTime;

/**
 * Pure /my card (RFC §3.7): pinned first, then recent; usage counters.
 */
final class MyCard
{
    /**
     * @param  list<array{host:string,label:?string,pinned:bool,use_count:int,last_used_at:?int}>  $targets
     * @param  array<int, string>  $rowRefs  visible-row index → callback_data for the context screen
     * @return array{text: string, keyboard: list<list<Button>>}
     */
    public static function render(int $chatId, array $targets, bool $autoCapture, int $maxTargets, array $rowRefs = []): array
    {
        $esc = HtmlRenderer::esc(...);

        if ($targets === []) {
            return [
                'text' => (new HtmlRenderer())->render('MY TARGETS', [
                    new Section('', [
                        'No remembered targets yet.',
                        'Run e.g. /whois example.org — hosts are saved automatically'.($autoCapture ? '' : ' (auto-save is OFF — use ⭐ on result cards)'),
                    ]),
                ], null),
                'keyboard' => [[new Button('« Menu', CallbackGrammar::encode('menu', $chatId))]],
            ];
        }

        usort($targets, static fn (array $a, array $b): int => [(bool) $b['pinned'], ($a['last_used_at'] ?? 0)]
            <=> [(bool) $a['pinned'], ($b['last_used_at'] ?? 0)]);

        $lines = [];
        foreach (array_slice($targets, 0, 12) as $row) {
            $pin = $row['pinned'] ? '⭐ ' : '';
            $label = is_string($row['label']) && $row['label'] !== '' ? $row['label'].' · ' : '';
            $last = is_int($row['last_used_at']) ? HumanTime::ageSince(gmdate('Y-m-d H:i:s', $row['last_used_at']), time()) : null;
            $lines[] = "{$pin}{$label}".$esc((string) $row['host'])." · {$row['use_count']} runs".(is_string($last) ? " · {$last}" : '');
        }

        if (count($targets) > 12) {
            $lines[] = '… +'.(count($targets) - 12).' more';
        }
        $lines[] = count($targets).'/'.$maxTargets;

        $keyboard = [];
        $numbered = [];
        foreach (array_slice($targets, 0, 9) as $i => $row) {
            $n = ($i + 1) % 10;
            if (isset($rowRefs[$i]) && is_string($rowRefs[$i])) {
                $numbered[] = new Button((string) $n, $rowRefs[$i]);
            }
        }
        foreach (array_chunk($numbered, 5) as $chunk) {
            $keyboard[] = $chunk;
        }
        $keyboard[] = [
            new Button('🧹 Clear all', CallbackGrammar::encode('clear', $chatId)),
            new Button('« Menu', CallbackGrammar::encode('menu', $chatId)),
        ];

        return [
            'text' => (new HtmlRenderer())->render('MY TARGETS', [new Section('', $lines, monospace: true)], null),
            'keyboard' => $keyboard,
        ];
    }
}
