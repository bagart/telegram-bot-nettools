<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;

/**
 * Pure /ping card (RFC §7.4): loss/latency/jitter table in a monospace block,
 * per-reply TTLs (feeds OsHeuristicProbe later), TCP-fallback mode label.
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class PingCard
{
    public static function render(ProbeResult $result, int $chatId, int $now, string $targetHost): array
    {
        $esc = HtmlRenderer::esc(...);
        $p = $result->payload;

        if ((bool) ($p['unreachable'] ?? false)) {
            return [
                'text' => (new HtmlRenderer())->render(
                    'PING · '.$esc($targetHost),
                    [new Section('', ['❌ Host unreachable or blocks probes ('.$esc(self::str($p['mode'])).' fallback)'])],
                    (new Footer())->add('ping', $result->latencyMs),
                ),
                'keyboard' => [MenuBackRow::row($chatId)],
            ];
        }

        $lines = [
            str_pad('sent', 12).(int) ($p['sent'] ?? 0),
            str_pad('received', 12).(int) ($p['received'] ?? 0),
            str_pad('loss', 12).number_format((float) ($p['loss_pct'] ?? 0), 1).'%',
        ];

        foreach (['min_ms' => 'min', 'avg_ms' => 'avg', 'max_ms' => 'max', 'jitter_ms' => 'jitter'] as $key => $label) {
            if (is_numeric($p[$key] ?? null)) {
                $lines[] = str_pad($label, 12).number_format((float) $p[$key], 2).' ms';
            }
        }

        $sections = [new Section('', $lines, monospace: true)];

        /** @var list<array{seq: int, ttl: ?int, ms: float}> $replies */
        $replies = array_values((array) ($p['replies'] ?? []));
        if ($replies !== []) {
            $replyLines = [];
            foreach ($replies as $reply) {
                $ttl = $reply['ttl'] !== null ? ' ttl '.(int) $reply['ttl'] : '';
                $replyLines[] = '#'.(int) $reply['seq'].str_pad('', 2).number_format((float) $reply['ms'], 2).' ms'.$ttl;
            }
            $sections[] = new Section('Replies', $replyLines, monospace: true);
        }

        $notes = [];
        if (($p['mode'] ?? '') === 'tcp') {
            $notes[] = 'ICMP unavailable — measured via TCP connect timing (port '.(int) ($p['tcp_port'] ?? 443).')';
        } else {
            $ttls = array_filter(array_column($replies, 'ttl'));
            if ($ttls !== []) {
                $notes[] = 'initial TTL ≈ '.self::ttlClass(min($ttls));
            }
        }

        if ($notes !== []) {
            $sections[] = new Section('', array_map(static fn (string $n): string => 'ℹ️ '.$esc($n), $notes));
        }

        $footer = (new Footer())->add(($p['mode'] ?? 'icmp') === 'tcp' ? 'tcp-connect' : 'icmp', $result->latencyMs);

        return [
            'text' => (new HtmlRenderer())->render(
                'PING · '.$esc($targetHost),
                $sections,
                $footer,
            ),
            'keyboard' => [MenuBackRow::row($chatId)],
        ];
    }

    /** Initial-TTL class table (RFC §7.10 preview): low-confidence by design. */
    private static function ttlClass(int $observedTtl): string
    {
        $class = match (true) {
            $observedTtl > 128 && $observedTtl <= 255 => 255,
            $observedTtl > 64 && $observedTtl <= 128 => 128,
            default => 64,
        };

        $guess = match ($class) {
            255 => 'network gear',
            128 => 'Windows',
            default => 'Linux/BSD',
        };

        return $observedTtl.' → ~'.$guess.' (low confidence)';
    }

    private static function str(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }
}
