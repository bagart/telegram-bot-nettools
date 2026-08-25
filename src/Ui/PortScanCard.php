<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;

/**
 * Pure /portscan card (admin-gated): open ports with banners, loud
 * acceptable-use disclaimer on every card (RFC §7.11).
 */
final class PortScanCard
{
    public static function render(\BAGArt\TelegramBotNettools\Results\ProbeResult $result, int $chatId, int $now, string $hostLabel): array
    {
        $esc = HtmlRenderer::esc(...);
        $p = $result->payload;

        /** @var list<array{port:int, state:string, ms:?float, banner:?string}> $open */
        $open = (array) ($p['open'] ?? []);

        if ($open === []) {
            $lines = ['No open ports found in the scanned range.'];
        } else {
            $lines = [];
            foreach ($open as $row) {
                $banner = is_string($row['banner']) && $row['banner'] !== ''
                    ? '  '.$esc(mb_substr(str_replace("\n", ' ', (string) $row['banner']), 0, 40))
                    : '';
                $lines[] = str_pad((string) $row['port'], 8).'OPEN'.$banner;
            }
        }

        $sections = [
            new Section('Open ('.count($open).'/'.(int) ($p['scanned'] ?? 0).' scanned)', $lines, monospace: true),
            new Section('', [
                '⚠️ ADMIN TOOL — scan only hosts you own or are authorised to test. All checks are logged.',
            ]),
        ];

        if ((bool) ($p['truncated'] ?? false)) {
            $sections[] = new Section('', ['ℹ️ Scan truncated at the wall-time cap — rerun for the rest of the range.']);
        }

        return [
            'text' => (new HtmlRenderer())->render('PORTSCAN · '.$esc($hostLabel), $sections, (new Footer())->add('tcp-connect', $result->latencyMs)),
            'keyboard' => [\BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow::row($chatId)],
        ];
    }
}
