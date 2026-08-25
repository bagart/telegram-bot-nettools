<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;

/**
 * Pure /sec card (RFC §7.8): header audit table ✅/❌, stack fingerprint
 * (labeled heuristic), security.txt, optional CORS/methods results.
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class SecCard
{
    private const array HEADERS = [
        'strict-transport-security' => ['HSTS', '🔒'],
        'content-security-policy' => ['CSP', '🛡'],
        'x-frame-options' => ['X-Frame-Options', '🖼'],
        'x-content-type-options' => ['X-Content-Type-Options', '📎'],
        'referrer-policy' => ['Referrer-Policy', '🔗'],
        'permissions-policy' => ['Permissions-Policy', '⚙️'],
    ];

    public static function render(ProbeResult $result, int $chatId, int $now, string $targetHost): array
    {
        $esc = HtmlRenderer::esc(...);
        $p = $result->payload;

        if (($p['error'] ?? null) !== null) {
            return [
                'text' => (new HtmlRenderer())->render(
                    'SEC · '.$esc($targetHost),
                    [new Section('', ['⚠️ Site unreachable from this network — headers audit impossible.'])],
                    (new Footer())->add('http', $result->latencyMs),
                ),
                'keyboard' => [MenuBackRow::row($chatId)],
            ];
        }

        $lines = [];
        foreach (self::HEADERS as $header => [$label, $icon]) {
            $present = isset(((array) $p['headers'])[$header]);
            $lines[] = "{$icon} ".str_pad($label, 22).($present ? '✅ set' : '❌ missing');
        }
        $sections = [new Section('Security headers', $lines, monospace: true)];

        /** @var list<array{severity:string,id:string,detail:string}> $findings */
        $findings = (array) ($p['findings'] ?? []);
        $sections = [...$sections, ...self::findingSections($findings)];

        $stack = (array) ($p['stack'] ?? []);
        if ($stack !== []) {
            $names = implode(', ', array_map(static fn ($s): string => $esc((string) $s['name']), $stack));
            $sections[] = new Section('', ["ℹ️ Stack (self-declared/heuristic): {$names}"]);
        }

        $txt = $p['security_txt'];
        if (is_array($txt) && ($txt['present'] ?? false)) {
            $contact = is_string($txt['contact'] ?? null) ? ' → '.$esc((string) $txt['contact']) : '';
            $sections[] = new Section('', ['✅ security.txt present'.$contact]);
        } else {
            $sections[] = new Section('', ['ℹ️ No /.well-known/security.txt — publish RFC 9116 contact (info-level)']);
        }

        $cors = $p['cors'];
        if (is_array($cors)) {
            $verdict = match ((string) $cors['verdict']) {
                'high' => '❌ '.$esc((string) $cors['detail']),
                default => '✅ CORS: '.$esc((string) $cors['detail']),
            };
            $sections[] = new Section('', [$verdict]);
        }

        $methods = $p['methods'];
        if (is_array($methods)) {
            $sections[] = new Section('', [
                ((bool) $methods['trace'] ? '⚠️ TRACE method enabled' : '✅ TRACE disabled')
                    .(is_string($methods['allow']) ? ' · Allow: '.$esc((string) $methods['allow']) : ''),
            ]);
        }

        return [
            'text' => (new HtmlRenderer())->render(
                'SEC · '.$esc($targetHost),
                $sections,
                (new Footer())->add('http', $result->latencyMs),
            ),
            'keyboard' => [MenuBackRow::row($chatId)],
        ];
    }

    /**
     * @param  list<array{severity:string,id:string,detail:string}>  $findings
     * @return list<Section>
     */
    private static function findingSections(array $findings): array
    {
        $groups = ['high' => [], 'warn' => [], 'info' => []];
        foreach ($findings as $finding) {
            $severity = (string) $finding['severity'];
            if (! isset($groups[$severity])) {
                continue;
            }
            $glyph = $severity === 'high' ? '❌' : ($severity === 'warn' ? '⚠️' : 'ℹ️');
            $groups[$severity][] = "• {$glyph} ".HtmlRenderer::esc((string) $finding['detail']);
        }

        $titles = ['high' => 'HIGH', 'warn' => 'WARN', 'info' => 'INFO'];
        $sections = [];
        foreach ($groups as $severity => $lines) {
            if ($lines !== []) {
                $sections[] = new Section($titles[$severity], $lines);
            }
        }

        return $sections;
    }
}
