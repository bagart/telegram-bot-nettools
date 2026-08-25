<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;

/**
 * Pure propagation-diff card: per-resolver A/AAAA answers, divergence flag,
 * authoritative markers.
 */
final class DnsPropagationCard
{
    /** @param array{host:string, rows:list<array{resolver:string, kind:string, value:?string, ttl:?int}>, divergent:bool, authoritative:list<string>} $result */
    public static function render(array $result): string
    {
        $esc = HtmlRenderer::esc(...);

        $byResolver = [];
        foreach ($result['rows'] as $row) {
            $byResolver[$row['resolver']][$row['kind']] = $row;
        }

        $lines = [];
        foreach ($byResolver as $resolver => $kinds) {
            $a = $kinds['A']['value'] ?? null;
            $aaaa = $kinds['AAAA']['value'] ?? null;
            $auth = in_array($resolver, $result['authoritative'], true) ? ' (auth)' : '';
            $lines[] = str_pad($resolver.$auth, 30)
                .str_pad((string) ($a ?? '—'), 18)
                .(string) ($aaaa ?? '—');
        }

        $verdict = $result['divergent']
            ? ['⚠️ Resolvers disagree — a change is still propagating (check low TTL windows).']
            : ['✅ All resolvers agree.'];

        return (new HtmlRenderer())->render(
            'PROPAGATION · '.$esc($result['host']),
            [new Section('', $lines, monospace: true), new Section('', $verdict)],
            null,
        );
    }
}
