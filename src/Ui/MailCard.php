<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Support\MailRecordsParser;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;

/**
 * Pure /mail card (§7.9): monospace record table with SPF lookup counter,
 * DMARC grading ladder, DKIM hits, modern-stack rows, findings grouped by
 * severity, degraded resolvers as warnings.
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class MailCard
{
    public static function render(ProbeResult $result, int $chatId, int $now, string $targetHost): array
    {
        unset($now);
        $esc = HtmlRenderer::esc(...);
        $p = $result->payload;

        $sections = [new Section('', self::tableLines($p, $esc), monospace: true)];

        /** @var list<array{severity: string, id: string, detail: string}> $findings */
        $findings = array_values((array) ($p['findings'] ?? []));
        foreach (self::findingSections($findings) as $section) {
            $sections[] = $section;
        }

        /** @var list<string> $degraded */
        $degraded = array_values(array_filter(array_map(strval(...), (array) ($result->degradedSources ?? []))));
        foreach ($degraded as $resolver) {
            $sections[] = new Section('', ['⚠️ Resolver '.$esc($resolver).' unavailable — partial results']);
        }

        return [
            'text' => (new HtmlRenderer())->render('MAIL · '.$esc($targetHost), $sections, (new Footer())->add('dns', $result->latencyMs)),
            'keyboard' => [MenuBackRow::row($chatId)],
        ];
    }

    /**
     * Label-padded 12-column record table.
     *
     * @param  array<string, mixed>  $p
     * @param  \Closure(string): string  $esc
     * @return list<string>
     */
    private static function tableLines(array $p, \Closure $esc): array
    {
        $lines = [];

        foreach (array_slice((array) ($p['mx'] ?? []), 0, 8) as $i => $entry) {
            $entry = (array) $entry;
            $flags = match (true) {
                (bool) ($entry['ip_literal'] ?? false) => '❌ IP literal',
                (bool) ($entry['is_cname'] ?? false) => '❌ CNAME alias',
                default => '✅',
            };
            $label = $i === 0 ? 'mx' : '';
            $lines[] = str_pad($label, 12).str_pad((string) ($entry['priority'] ?? 0), 3).$esc((string) ($entry['host'] ?? '')).'  '.$flags;
        }
        if (($p['mx'] ?? []) === []) {
            $lines[] = str_pad('mx', 12).'❌ none published';
        }

        $spf = is_array($p['spf'] ?? null) ? (array) $p['spf'] : null;
        if ($spf === null) {
            $lines[] = str_pad('spf', 12).'❌ missing';
        } else {
            $lookups = (int) ($spf['lookups'] ?? 0);
            $icon = match (true) {
                (bool) ($spf['multiple'] ?? false) => '❌',
                $lookups > MailRecordsParser::SPF_LOOKUP_LIMIT || (($spf['errors'] ?? []) !== []) => '⚠️',
                default => '✅',
            };
            $verdict = $lookups > MailRecordsParser::SPF_LOOKUP_LIMIT ? ' ❌' : ($lookups > 7 ? ' ⚠️' : '');
            $suffix = (bool) ($spf['multiple'] ?? false) ? ' · MULTIPLE RECORDS ❌' : '';
            $lines[] = str_pad('spf', 12).$icon.' '.$esc(self::shortRecord((string) ($spf['record'] ?? '')))
                ." · {$lookups} lookups{$verdict} (limit ".MailRecordsParser::SPF_LOOKUP_LIMIT."){$suffix}";
        }

        $dmarc = is_array($p['dmarc'] ?? null) ? (array) $p['dmarc'] : [];
        if ((bool) ($dmarc['missing'] ?? true)) {
            $lines[] = str_pad('dmarc', 12).'⚠️ missing — spoofed mail will land in inboxes';
        } else {
            $policy = is_string($dmarc['policy'] ?? null) ? (string) $dmarc['policy'] : null;
            $rua = (bool) ($dmarc['rua'] ?? false);
            $icon = $policy === 'reject' ? '✅' : ($policy === null ? '❌' : '⚠️');
            $line = "{$icon} p=".($policy ?? '?')
                .($rua ? ' · rua ✓' : '')
                .(isset($dmarc['pct']) && is_int($dmarc['pct']) ? ' · pct '.$dmarc['pct'] : '');
            if ($policy === 'none') {
                $line .= ' — ladder: none → quarantine → reject';
            }
            $lines[] = str_pad('dmarc', 12).$esc($line);
        }

        /** @var list<string> $dkim */
        $dkim = array_values(array_filter(array_map(strval(...), (array) ($p['dkim'] ?? []))));
        $lines[] = str_pad('dkim', 12).($dkim === []
            ? 'ℹ️ none found'
            : '✅ '.$esc(implode(', ', $dkim)));

        $sts = is_array($p['mta_sts'] ?? null) ? (array) $p['mta_sts'] : [];
        $lines[] = str_pad('mta-sts', 12).((bool) ($sts['present'] ?? false)
            ? '✅'.(is_string($sts['id'] ?? null) && $sts['id'] !== '' ? ' id='.$esc((string) $sts['id']) : '')
            : 'ℹ️ absent');

        $tlsRua = is_string($p['tls_rpt'] ?? null) ? (string) $p['tls_rpt'] : null;
        $lines[] = str_pad('tls-rpt', 12).($tlsRua !== null ? '✅ '.$esc(self::shortRecord($tlsRua, 40)) : 'ℹ️ absent');

        $lines[] = str_pad('bimi', 12).((bool) ($p['bimi'] ?? false) ? '✅ present' : 'ℹ️ absent');

        if (is_array($p['smtp'] ?? null)) {
            $smtp = (array) $p['smtp'];
            $reachable = (bool) ($smtp['reachable'] ?? false);
            $starttls = (bool) ($smtp['starttls'] ?? false);
            $cert = is_int($smtp['cert_days_left'] ?? null) ? ' · cert '.((int) $smtp['cert_days_left']).'d' : '';
            $state = ! $reachable ? '⚠️ unreachable' : ($starttls ? "✅ STARTTLS{$cert}" : '❌ no STARTTLS');
            $lines[] = str_pad('smtp', 12).$esc($state);
        }

        return $lines;
    }

    /**
     * @param  list<array{severity: string, id: string, detail: string}>  $findings
     * @return list<Section>
     */
    private static function findingSections(array $findings): array
    {
        $groups = [
            'high' => ['title' => '❌ High', 'icon' => '❌'],
            'warn' => ['title' => '⚠️ Warnings', 'icon' => '⚠️'],
            'info' => ['title' => 'ℹ️ Info', 'icon' => 'ℹ️'],
        ];

        $sections = [];
        foreach ($groups as $severity => $meta) {
            $entries = array_values(array_filter($findings, static fn (array $f): bool => $f['severity'] === $severity));
            if ($entries === []) {
                continue;
            }
            $sections[] = new Section(
                $meta['title'].' ('.count($entries).')',
                array_map(static fn (array $f): string => $meta['icon'].' '.HtmlRenderer::esc((string) $f['detail']), $entries),
            );
        }

        return $sections;
    }

    private static function shortRecord(string $record, int $max = 44): string
    {
        $record = trim($record);

        return mb_strlen($record) > $max ? mb_substr($record, 0, $max - 1).'…' : $record;
    }
}
