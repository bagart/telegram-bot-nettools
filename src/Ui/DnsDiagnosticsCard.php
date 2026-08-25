<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;

/**
 * Pure lame-delegation / open-resolver diagnostics card.
 */
final class DnsDiagnosticsCard
{
    /** @param array{host:string, ns_rows:list<array{ns:string, ip:?string, authoritative:bool, open_resolver:?bool}>, lame:list<string>} $result */
    public static function render(array $result): string
    {
        $esc = HtmlRenderer::esc(...);

        if ($result['ns_rows'] === []) {
            return (new HtmlRenderer())->render('DIAGNOSTICS · '.$esc($result['host']), [
                new Section('', ['⚠️ NS query failed — zone unreachable or no delegation found.']),
            ], null);
        }

        $lines = [];
        foreach ($result['ns_rows'] as $row) {
            $auth = $row['authoritative'] ? '✅ auth' : '❌ lame';
            $open = match ($row['open_resolver']) {
                true => ' · ⚠️ open recursion',
                false => ' · closed',
                default => '',
            };
            $lines[] = str_pad((string) $row['ns'], 32)."{$auth}{$open}";
        }

        $verdict = [];
        if ($result['lame'] !== []) {
            $verdict[] = '⚠️ Lame delegation detected: '.HtmlRenderer::esc(implode(', ', $result['lame'])).' — fix registrar glue + NS set.';
        } else {
            $verdict[] = '✅ All NS answer authoritatively for the zone.';
        }
        foreach ($result['ns_rows'] as $row) {
            if ($row['open_resolver'] === true) {
                $verdict[] = '⚠️ '.HtmlRenderer::esc((string) $row['ns']).' resolves third-party names — disable world recursion (amplification-abuse risk).';
                break;
            }
        }

        return (new HtmlRenderer())->render(
            'DIAGNOSTICS · '.$esc($result['host']),
            [new Section('', $lines, monospace: true), new Section('', $verdict)],
            null,
        );
    }
}
