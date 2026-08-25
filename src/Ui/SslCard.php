<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Support\HumanTime;

/**
 * Pure /ssl card (RFC §7.7): verdict-first lines per audit group, findings
 * grouped by severity, monospace certificate summary block. A target without
 * TLS is a distinct result — shown as such, never an error card.
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class SslCard
{
    private const int LABEL_WIDTH = 12;

    public static function render(ProbeResult $result, int $chatId, int $now, string $targetHost): array
    {
        $esc = HtmlRenderer::esc(...);
        $p = $result->payload;

        $footer = (new Footer())->add('tls', $result->latencyMs);

        if (! (bool) ($p['has_tls'] ?? false)) {
            $error = self::str($p['error'] ?? null);
            $detail = $error !== null ? ' ('.$esc($error).')' : '';

            return [
                'text' => (new HtmlRenderer())->render(
                    'SSL · '.$esc($targetHost),
                    [new Section('', ['ℹ️ No TLS service detected on port 443'.$detail])],
                    $footer,
                ),
                'keyboard' => [],
            ];
        }

        /** @var list<array{severity: string, id: string, detail: string}> $findings */
        $findings = array_values((array) ($p['findings'] ?? []));
        $severityOf = [];
        foreach ($findings as $finding) {
            $severityOf[$finding['id']] = $finding['severity'];
        }
        $verdict = static fn (string ...$ids): string => match (true) {
            in_array('high', array_map(static fn (string $id): string => $severityOf[$id] ?? '', $ids), true) => '❌',
            in_array('warn', array_map(static fn (string $id): string => $severityOf[$id] ?? '', $ids), true) => '⚠️',
            default => '✅',
        };

        /** @var array<string, mixed> $cert */
        $cert = (array) ($p['cert'] ?? []);
        $lines = [
            self::validityLine($cert, $now, $verdict('expired', 'not_valid_yet', 'expiring_soon', 'expiring', 'long_lifetime')),
            self::keyLine($cert, $verdict('weak_key', 'weak_sig')),
            self::hostnameLine($cert, $targetHost, $p, $verdict('hostname_mismatch', 'self_signed')),
            self::chainLine($p, $verdict('incomplete_chain')),
            self::protocolsLine($p, $verdict('legacy_protocol')),
            self::alpnLine($p),
        ];

        if ($findings === []) {
            $lines[] = '✅ All checks passed';
        }

        $sections = [new Section('', $lines)];

        $summaryLines = self::certSummary($cert, $now);
        if ($summaryLines !== []) {
            $sections[] = new Section('', $summaryLines, monospace: true);
        }

        $findingLines = self::findingGroups($findings, $esc);
        if ($findingLines !== []) {
            $sections[] = new Section('', $findingLines);
        }

        /** @var list<string> $degraded */
        $degraded = array_values(array_filter(array_map(strval(...), (array) $result->degradedSources)));
        foreach ($degraded as $source) {
            $sections[] = new Section('', ['⚠️ Source '.$esc($source).' unavailable — partial results']);
        }

        return [
            'text' => (new HtmlRenderer())->render('SSL · '.$esc($targetHost), $sections, $footer),
            'keyboard' => [],
        ];
    }

    /**
     * @param  array<string, mixed>  $cert
     */
    private static function validityLine(array $cert, int $now, string $emoji): string
    {
        $expiresOn = gmdate('Y-m-d', (int) ($cert['valid_to'] ?? 0));

        if ((int) ($cert['valid_to'] ?? 0) < $now) {
            return $emoji.' Expired: '.$expiresOn.' — '.HumanTime::ageSince($expiresOn, $now).' ⚠️';
        }

        return $emoji.' Expires: '.$expiresOn.' — '.(HumanTime::countdownTo($expiresOn, $now) ?? '?');
    }

    /**
     * @param  array<string, mixed>  $cert
     */
    private static function keyLine(array $cert, string $emoji): string
    {
        $parts = [];
        $keyAlg = self::str($cert['key_alg'] ?? null);
        $bits = is_int($cert['key_bits'] ?? null) ? $cert['key_bits'] : null;
        if ($keyAlg !== null) {
            $parts[] = $keyAlg.(is_int($bits) ? ' '.$bits.' bits' : '');
        }
        $sigAlg = self::str($cert['sig_alg'] ?? null);
        if ($sigAlg !== null) {
            $parts[] = 'sig '.$sigAlg;
        }

        return $emoji.' Key: '.HtmlRenderer::esc($parts === [] ? 'unknown' : implode(' · ', $parts));
    }

    /**
     * @param  array<string, mixed>  $cert
     * @param  array<string, mixed>  $payload
     */
    private static function hostnameLine(array $cert, string $targetHost, array $payload, string $emoji): string
    {
        if ((bool) ($payload['self_signed'] ?? false)) {
            return $emoji.' Hostname: self-signed certificate for '.self::namesHint($cert);
        }

        return $emoji.' Hostname: matches '.HtmlRenderer::esc($targetHost)
            .' ('.HtmlRenderer::esc(self::namesHint($cert)).')';
    }

    /**
     * @param  array<string, mixed>  $cert
     */
    private static function namesHint(array $cert): string
    {
        $candidates = array_values(array_filter([
            self::str($cert['subject_cn'] ?? null),
            ...array_values((array) ($cert['san'] ?? [])),
        ]));
        $shown = implode(', ', array_slice($candidates, 0, 3));

        return HtmlRenderer::esc($shown !== '' ? $shown : 'no names');
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private static function chainLine(array $payload, string $emoji): string
    {
        $count = (int) ($payload['chain_count'] ?? 0);

        return $emoji.' Chain: '.$count.' certificate'.($count === 1 ? '' : 's');
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private static function protocolsLine(array $payload, string $emoji): string
    {
        $offered = array_values((array) ($payload['offered_protocols'] ?? []));
        $negotiated = self::str($payload['protocol'] ?? null);
        $shown = $offered !== [] ? implode(', ', $offered) : ($negotiated ?? 'unknown');

        return $emoji.' Protocols: '.HtmlRenderer::esc($shown);
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private static function alpnLine(array $payload): ?string
    {
        $alpn = array_values(array_filter(array_map(
            static fn (mixed $proto): string => is_scalar($proto) ? trim((string) $proto) : '',
            (array) ($payload['alpn'] ?? []),
        )));

        if ($alpn === []) {
            return null;
        }

        return in_array('h2', $alpn, true)
            ? '✅ ALPN: h2 · HTTP/2 available'
            : 'ℹ️ ALPN: '.HtmlRenderer::esc(implode(', ', $alpn));
    }

    /**
     * @param  array<string, mixed>  $cert
     * @return list<string>
     */
    private static function certSummary(array $cert, int $now): array
    {
        if ($cert === []) {
            return [];
        }

        $issuer = implode(' / ', array_filter([
            self::str($cert['issuer_cn'] ?? null),
            self::str($cert['issuer_org'] ?? null),
        ]));

        $rows = [
            ['subject', (string) ($cert['subject_cn'] ?? '')],
            ['issuer', $issuer],
            ['issued', gmdate('Y-m-d', (int) ($cert['valid_from'] ?? 0))],
            ['expires', gmdate('Y-m-d', (int) ($cert['valid_to'] ?? 0))],
            ['serial', (string) ($cert['serial'] ?? '')],
            ['fp-sha256', (string) ($cert['sha256_fp'] ?? '')],
        ];

        $lines = [];
        foreach ($rows as [$label, $value]) {
            $lines[] = str_pad($label, self::LABEL_WIDTH).HtmlRenderer::esc($value);
        }

        return $lines;
    }

    /**
     * @param  list<array{severity: string, id: string, detail: string}>  $findings
     * @return list<string>
     */
    private static function findingGroups(array $findings, \Closure $esc): array
    {
        $heads = ['high' => '❌ HIGH', 'warn' => '⚠️ WARN', 'info' => 'ℹ️ INFO'];
        $lines = [];

        foreach (['high', 'warn', 'info'] as $severity) {
            $group = array_values(array_filter(
                $findings,
                static fn (array $finding): bool => ($finding['severity'] ?? '') === $severity,
            ));
            if ($group === []) {
                continue;
            }

            $lines[] = $heads[$severity];
            foreach ($group as $finding) {
                $lines[] = '• '.HtmlRenderer::esc($finding['detail']);
            }
        }

        return $lines;
    }

    private static function str(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }
}
