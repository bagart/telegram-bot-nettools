<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Support\AsnClassifier;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;

/**
 * Pure /ip card (RFC §7.3): geo block, ASN + type classification, rDNS with
 * forward-confirmation, honest v6 note, degraded sources as warnings.
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class IpCard
{
    public static function render(ProbeResult $result, int $chatId, int $now, string $targetHost): array
    {
        $esc = HtmlRenderer::esc(...);
        $p = $result->payload;

        $lines = [];
        if (($p['reserved'] ?? null) !== null) {
            $lines[] = '🏷 Reserved range — no geo data ('.$esc((string) $p['reserved']).')';
        }

        if ($p['country'] !== null || $p['city'] !== null) {
            $place = implode(', ', array_filter([$p['country'], $p['region'], $p['city']], static fn ($v) => is_string($v) && $v !== ''));
            $lines[] = '🌍 '.$esc($place);
        }
        if (is_float($p['lat']) || is_int($p['lat'])) {
            $lines[] = '📍 '.number_format((float) $p['lat'], 2).', '.number_format((float) $p['lon'], 2);
        }

        $asnLine = null;
        if ($p['asn'] !== null) {
            $asnLine = 'AS'.(int) $p['asn'].(is_string($p['asn_org']) && $p['asn_org'] !== '' ? ' · '.$esc($p['asn_org']) : '');
        } elseif (is_string($p['org']) && $p['org'] !== '') {
            $asnLine = $esc($p['org']);
        }
        if ($asnLine !== null) {
            $type = self::str($p['type']);
            $lines[] = $asnLine.($type !== null && $type !== 'unknown'
                ? '  ['.AsnClassifier::emoji($type).' '.$esc($type).']'
                : '');
        }

        $rpki = self::str($p['rpki'] ?? null);
        if ($rpki === 'invalid') {
            $lines[] = '❌ RPKI: ROA invalid for the announced prefix';
        } elseif ($rpki === 'valid') {
            $lines[] = '✅ RPKI valid';
        }

        if (is_string($p['ptr']) && $p['ptr'] !== '') {
            $confirmed = match ($p['ptr_confirmed']) {
                true => ' ✅ forward-confirmed',
                false => ' ⚠️ no forward confirmation',
                default => '',
            };
            $lines[] = '↩️ PTR: '.$esc(self::str($p['ptr'])).$confirmed;
        }

        $v6 = self::str($p['v6_reach'] ?? null);
        if ($v6 === 'no-route') {
            $lines[] = 'ℹ️ No v6 route from this server — reachability unknown';
        } elseif ($v6 === 'reachable') {
            $lines[] = '✅ IPv6 reachable from this server';
        }

        if ($lines === []) {
            $lines[] = 'No geo/ASN data available for this address.';
        }

        $sections = [new Section('', $lines)];

        /** @var list<string> $degraded */
        $degraded = array_values(array_filter(array_map(strval(...), (array) $result->degradedSources)));
        foreach ($degraded as $source) {
            $sections[] = new Section('', ['⚠️ Source '.$esc($source).' unavailable — partial results']);
        }

        $footer = new Footer();
        foreach (array_unique((array) ($p['source'] ?? [])) as $sourceName) {
            $footer->add((string) $sourceName, $result->latencyMs);
        }
        if ($footer->isEmpty()) {
            $footer->add('local', $result->latencyMs);
        }

        return [
            'text' => (new HtmlRenderer())->render('IP · '.$esc($targetHost), $sections, $footer),
            'keyboard' => [MenuBackRow::row($chatId)],
        ];
    }

    private static function str(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }
}
