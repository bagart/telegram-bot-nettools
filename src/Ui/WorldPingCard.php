<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;

/**
 * Pure world-ping card: per-vantage latency table, honest degrade note.
 *
 * @param array{ok:bool, error:?string, nodes:list<array{node:string, region:string, ms:?int}>} $outcome
 */
final class WorldPingCard
{
    public static function render(array $outcome, string $host): string
    {
        $esc = HtmlRenderer::esc(...);

        if (! $outcome['ok']) {
            return (new HtmlRenderer())->render('WORLD PING · '.$esc($host), [
                new Section('', ['⚠️ '.HtmlRenderer::esc((string) $outcome['error'])]),
            ], null);
        }

        $lines = [];
        foreach ($outcome['nodes'] as $node) {
            $ms = is_int($node['ms']) ? number_format((float) $node['ms']).' ms' : 'timeout';
            $lines[] = str_pad(HtmlRenderer::esc((string) $node['region']), 28).$ms;
        }

        $times = array_filter(array_column($outcome['nodes'], 'ms'));

        return (new HtmlRenderer())->render(
            'WORLD PING · '.$esc($host),
            [
                new Section('', $lines ?: ['no nodes answered'], monospace: true),
                new Section('', [$times === [] ? '' : 'min '.min($times).' ms · max '.max($times).' ms across '.count($times).' vantage points']),
            ],
            null,
        );
    }
}
