<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;

/**
 * Pure /port card (RFC §7.14): open/closed/filtered verdict + latency +
 * banner excerpt; closed-vs-filtered wording distinguishes RST from silence.
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class PortCard
{
    public static function render(ProbeResult $result, int $chatId, int $now, string $targetHost): array
    {
        $esc = HtmlRenderer::esc(...);
        $p = $result->payload;

        $state = (string) ($p['state'] ?? 'filtered');
        $icon = match ($state) {
            'open' => '✅',
            'closed' => '⛔',
            default => '🌫',
        };

        $lines = [
            str_pad('port', 8).$p['host'].':'.(int) ($p['port'] ?? 0),
            str_pad('state', 8)."{$icon} {$state}",
        ];

        if (is_numeric($p['latency_ms'] ?? null)) {
            $lines[] = str_pad('latency', 8).number_format((float) $p['latency_ms'], 1).' ms';
        }
        if (is_string($p['protocol']) && $p['protocol'] !== '') {
            $lines[] = str_pad('protocol', 8).(string) $p['protocol'];
        }
        if (is_string($p['hint']) && $p['hint'] !== '') {
            $lines[] = '';
            $lines[] = 'ℹ️ '.HtmlRenderer::esc((string) $p['hint']);
        }

        $banner = $p['banner'] ?? null;
        if (is_string($banner) && trim($banner) !== '') {
            foreach (explode("\n", wordwrap(trim($banner), 60, "\n", true)) as $i => $line) {
                if ($i >= 4) {
                    $lines[] = str_repeat(' ', 8).'…';

                    break;
                }
                $lines[] = str_pad('', 8).HtmlRenderer::esc($line);
            }
        }

        $footer = (new Footer())->add('tcp-connect', $result->latencyMs);

        return [
            'text' => (new HtmlRenderer())->render(
                'PORT · '.$esc($targetHost),
                [new Section('', $lines, monospace: true)],
                $footer,
            ),
            'keyboard' => [MenuBackRow::row($chatId)],
        ];
    }
}
