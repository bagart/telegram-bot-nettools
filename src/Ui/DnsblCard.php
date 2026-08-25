<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;

/**
 * Pure /dnsbl card (admin-gated): listed zones with answers, clean summary.
 */
final class DnsblCard
{
    public static function render(\BAGArt\TelegramBotNettools\Results\ProbeResult $result, int $chatId, int $now, string $hostLabel): array
    {
        $esc = HtmlRenderer::esc(...);
        $p = $result->payload;

        if (($p['error'] ?? null) === 'ipv4-required') {
            return [
                'text' => (new HtmlRenderer())->render('DNSBL · '.$esc($hostLabel), [
                    new Section('', ['ℹ️ DNSBL checks apply to IPv4 addresses only.']),
                ], null),
                'keyboard' => [\BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow::row($chatId)],
            ];
        }

        /** @var list<array{zone:string, answer:string}> $listed */
        $listed = (array) ($p['listed'] ?? []);

        if ($listed === []) {
            $lines = ["✅ Clean — not listed on {$p['checked']}/{$p['zones_total']} zones."];
            $mono = false;
        } else {
            $lines = array_map(
                static fn (array $row): string => str_pad(HtmlRenderer::esc((string) $row['zone']), 30).'❌ '.$esc((string) $row['answer']),
                $listed,
            );
            $mono = true;
        }

        return [
            'text' => (new HtmlRenderer())->render(
                'DNSBL · '.$esc($hostLabel),
                [new Section('Listed ('.count($listed).')', $lines, monospace: $mono)],
                (new Footer())->add('dns', $result->latencyMs),
            ),
            'keyboard' => [\BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow::row($chatId)],
        ];
    }
}
