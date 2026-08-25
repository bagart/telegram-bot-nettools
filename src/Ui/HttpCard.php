<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;

/**
 * Pure /http card (RFC §7.13): final status + version, redirect chain with
 * per-hop timing, size/encoding, server banner. Transport failures are
 * distinguished (refused vs timeout vs TLS).
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class HttpCard
{
    public static function render(ProbeResult $result, int $chatId, int $now, string $targetHost): array
    {
        $esc = HtmlRenderer::esc(...);
        $p = $result->payload;

        if (($p['error'] ?? null) !== null) {
            $text = match ((string) $p['error']) {
                'refused' => '❌ Connection refused — nothing answering on that port.',
                'timeout' => '⏳ Timed out — server too slow or filtering probes.',
                'tls' => '🔒 TLS handshake failed — invalid/expired certificate or protocol mismatch.',
                default => '⚠️ Request failed — host unreachable from this network.',
            };

            return [
                'text' => (new HtmlRenderer())->render('HTTP · '.$esc($targetHost), [new Section('', [$text])], (new Footer())->add('http', $result->latencyMs)),
                'keyboard' => [MenuBackRow::row($chatId)],
            ];
        }

        $status = (int) ($p['status'] ?? 0);
        $statusIcon = $status < 400 ? '✅' : '⚠️';

        $lines = [
            str_pad('status', 12)."{$statusIcon} {$status}".(is_string($p['http_version']) ? ' · HTTP/'.HtmlRenderer::esc((string) $p['http_version']) : ''),
        ];

        if (is_numeric($p['total_ms'] ?? null)) {
            $lines[] = str_pad('total time', 12).(int) $p['total_ms'].' ms';
        }
        if (is_string($p['content_type'])) {
            $lines[] = str_pad('type', 12).$esc(self::shortContentType((string) $p['content_type']));
        }
        if (is_int($p['bytes'] ?? null)) {
            $size = self::humanBytes((int) $p['bytes']);
            if (is_int($p['content_length'] ?? null) && (int) $p['content_length'] !== (int) $p['bytes']) {
                $size .= ' of '.self::humanBytes((int) $p['content_length']).' declared';
            }
            if ((bool) ($p['truncated'] ?? false)) {
                $size .= ' (64 KB read cap)';
            }
            $lines[] = str_pad('size', 12).$esc($size);
        }
        if (is_string($p['content_encoding']) && $p['content_encoding'] !== '') {
            $lines[] = str_pad('compression', 12).$esc((string) $p['content_encoding']);
        }
        if (is_string($p['server']) && $p['server'] !== '') {
            $lines[] = str_pad('server', 12).$esc((string) $p['server']);
        }

        $sections = [new Section('', $lines, monospace: true)];

        /** @var list<array{url: string, status: int, ms: int}> $chain */
        $chain = array_values((array) ($p['redirect_chain'] ?? []));
        if (count($chain) > 1) {
            $hopLines = [];
            foreach ($chain as $i => $hop) {
                $host = parse_url($hop['url'], PHP_URL_HOST) ?: $hop['url'];
                $arrow = $i === count($chain) - 1 ? '→ ' : '↳ ';
                $hopLines[] = $arrow.$esc((string) $host).' ['.(int) $hop['status'].', '.(int) $hop['ms'].' ms]';
            }
            $sections[] = new Section('Redirect chain ('.count($chain).' hops)', $hopLines, monospace: true);
        }

        if (is_array($p['blocked_redirect'] ?? null)) {
            /** @var array{url: string, reason: string} $blocked */
            $blocked = $p['blocked_redirect'];
            $reason = str_contains((string) $blocked['reason'], 'downgrade')
                ? 'https → http downgrade denied'
                : (str_contains((string) $blocked['reason'], 'ssrf_blocked')
                    ? 'target is a private/reserved address (SSRF guard)'
                    : 'unsafe redirect target');
            $blockedHost = parse_url($blocked['url'], PHP_URL_HOST) ?: $blocked['url'];
            $sections[] = new Section('', ['⛔ '.$esc((string) $blockedHost).' — redirect blocked: '.$reason]);
        } elseif (count($chain) <= 1) {
            if ($status >= 300 && $status < 400) {
                $sections[] = new Section('', ['ℹ️ Redirect without a usable Location header']);
            } elseif ($status === 404) {
                $sections[] = new Section('', ['ℹ️ Not found — page missing (a result, not a probe error)']);
            } elseif ($status >= 500) {
                $sections[] = new Section('', ['ℹ️ Server-side error — the site itself is failing']);
            }
        }

        $footer = (new Footer())->add('http', $result->latencyMs);

        return [
            'text' => (new HtmlRenderer())->render('HTTP · '.$esc($targetHost), $sections, $footer),
            'keyboard' => [MenuBackRow::row($chatId)],
        ];
    }

    private static function shortContentType(string $contentType): string
    {
        return trim(explode(';', $contentType, 2)[0]);
    }

    public static function humanBytes(int $bytes): string
    {
        if ($bytes < 1024) {
            return "{$bytes} B";
        }
        if ($bytes < 1048576) {
            return round($bytes / 1024, 1).' KB';
        }

        return round($bytes / 1048576, 2).' MB';
    }

}
