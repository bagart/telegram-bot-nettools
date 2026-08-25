<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Paginator;
use BAGArt\TelegramBotNettools\Formatting\Section;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Support\AsnClassifier;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;

/**
 * Pure /asn card (RFC §7.15): org/registry/country, prefix counts + sample
 * (v4/v6), top peers by power; overflow paginates (prefix lists are long).
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class AsnCard
{
    private const int PREFIX_SHOW = 50;

    public static function render(ProbeResult $result, int $chatId, int $now, string $targetLabel): array
    {
        $esc = HtmlRenderer::esc(...);
        $p = $result->payload;

        $asn = (int) ($p['asn'] ?? 0);

        if (($p['not_announced'] ?? false) === true || $asn === 0) {
            return [
                'text' => (new HtmlRenderer())->render(
                    'ASN · '.$esc($targetLabel),
                    [new Section('', ['ℹ️ ASN not announced — the address may be unallocated or un-routed.'])],
                    (new Footer())->add('asn', $result->latencyMs),
                ),
                'keyboard' => [MenuBackRow::row($chatId)],
            ];
        }

        $lines = [
            str_pad('ASN', 10).'AS'.$asn,
        ];
        if (is_string($p['org']) && $p['org'] !== '') {
            $type = self::str($p['type'] ?? null);
            $lines[] = str_pad('org', 10).$esc((string) $p['org']).($type !== null && $type !== 'unknown'
                ? '  ['.AsnClassifier::emoji($type).' '.$esc($type).']'
                : '');
        }
        if (self::str($p['country']) !== null) {
            $lines[] = str_pad('country', 10).(string) $p['country'];
        }
        if (self::str($p['registry']) !== null) {
            $lines[] = str_pad('registry', 10).(string) $p['registry'];
        }
        if (self::str($p['allocated']) !== null) {
            $lines[] = str_pad('allocated', 10).(string) $p['allocated'];
        }
        $rpki = self::str($p['rpki'] ?? null);
        if ($rpki === 'invalid') {
            $lines[] = str_pad('rpki', 10).'❌ invalid';
        } elseif ($rpki === 'valid') {
            $lines[] = str_pad('rpki', 10).'✅ valid';
        }

        /** @var array{v4: int, v6: int} $counts */
        $counts = ['v4' => (int) ($p['prefix_counts']['v4'] ?? 0), 'v6' => (int) ($p['prefix_counts']['v6'] ?? 0)];
        $lines[] = str_pad('prefixes', 10)."{$counts['v4']} IPv4 · {$counts['v6']} IPv6";

        $sections = [new Section('', $lines, monospace: true)];

        /** @var list<string> $prefixes */
        $prefixes = array_values((array) ($p['prefixes'] ?? []));
        if ($prefixes !== []) {
            $shown = array_slice($prefixes, 0, self::PREFIX_SHOW);
            $prefixLines = array_map(static fn (string $prefix): string => HtmlRenderer::esc($prefix), $shown);
            if (count($prefixes) > count($shown)) {
                $prefixLines[] = '… +'.(count($prefixes) - count($shown)).' more';
            }
            $sections[] = new Section('Announced prefixes', $prefixLines, monospace: true);
        }

        /** @var list<array{asn: int, holder: string, power: int}> $peers */
        $peers = array_values((array) ($p['peers'] ?? []));
        if ($peers !== []) {
            $peerLines = [];
            foreach ($peers as $peer) {
                $peerLines[] = str_pad('AS'.(int) $peer['asn'], 11).HtmlRenderer::esc((string) $peer['holder']).' ('.(int) $peer['power'].')';
            }
            $sections[] = new Section('Top peers', $peerLines, monospace: true);
        }

        $footer = new Footer();
        foreach (array_unique((array) ($p['source'] ?? [])) as $sourceName) {
            $footer->add((string) $sourceName, $result->latencyMs);
        }
        if ($footer->isEmpty()) {
            $footer->add('asn', $result->latencyMs);
        }

        $pages = (new Paginator())->paginate(
            $sections,
            HtmlRenderer::MAX_CHARS,
            'ASN · '.$esc($targetLabel),
            $footer->render(),
        );

        return [
            'text' => (new HtmlRenderer())->render('ASN · '.$esc($targetLabel), $pages === [] ? [] : $pages[0], $footer),
            'keyboard' => [MenuBackRow::row($chatId)],
        ];
    }

    private static function str(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }
}
