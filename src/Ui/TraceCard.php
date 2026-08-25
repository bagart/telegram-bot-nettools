<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;

/**
 * Pure /trace card (RFC §7.5): hop table with ASN per hop, firewalled hops as
 * `* * *`, destination-reached marker; overflow paginates.
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class TraceCard
{
    public static function render(ProbeResult $result, int $chatId, int $now, string $targetHost): array
    {
        $esc = HtmlRenderer::esc(...);
        $p = $result->payload;

        /** @var list<array{n: int, ip: ?string, asn: int|null, ms: list<float>, timeout: bool}> $hops */
        $hops = array_values((array) ($p['hops'] ?? []));

        $lines = [];
        foreach ($hops as $hop) {
            $prefix = str_pad((string) $hop['n'], 3);
            if ($hop['timeout']) {
                $lines[] = $prefix.'* * *';

                continue;
            }

            $asn = is_int($hop['asn']) ? ' AS'.(int) $hop['asn'] : '';
            $rtts = implode('  ', array_map(static fn (float $ms): string => number_format($ms, 1).' ms', $hop['ms']));
            $lines[] = $prefix.$esc(self::str($hop['ip'])).$asn.'  '.$rtts;
        }

        if ($lines === []) {
            $lines[] = 'No hops answered — target unreachable or trace blocked.';
        }

        $sections = [new Section('', $lines, monospace: true)];

        $notes = [];
        if ((bool) ($p['reached'] ?? false)) {
            $notes[] = '✅ Destination reached in '.(int) ($p['hop_count'] ?? 0).' hops';
        } elseif ((bool) ($p['truncated'] ?? false)) {
            $notes[] = 'Truncated at '.(int) ($p['max_hops'] ?? 0).' hops — destination did not answer';
        } else {
            $notes[] = 'Path ended before the destination answered';
        }
        if (($p['binary'] ?? '') === 'tracepath') {
            $notes[] = 'measured with tracepath';
        }
        $sections[] = new Section('', array_map(static fn (string $n): string => HtmlRenderer::esc($n), $notes));

        $footer = (new Footer())->add('traceroute', $result->latencyMs);

        return [
            'text' => (new HtmlRenderer())->render('TRACE · '.$esc($targetHost), $sections, $footer),
            'keyboard' => [MenuBackRow::row($chatId)],
        ];
    }

    private static function str(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }
}
