<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;

/**
 * Pure /dns card per the §3.3 mockup: record matrix in a monospace block,
 * per-type statuses, DNSSEC AD hint, degraded resolvers as warnings.
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class DnsCard
{
    public static function render(ProbeResult $result, int $chatId, int $now, string $targetHost): array
    {
        $esc = HtmlRenderer::esc(...);
        $payload = $result->payload;
        /** @var array<string, list<string>> $records */
        $records = (array) ($payload['records'] ?? []);
        /** @var array<string, string> $statuses */
        $statuses = (array) ($payload['statuses'] ?? []);

        $lines = [];
        foreach ($records as $type => $values) {
            $ttl = isset($payload['ttls'][$type]) ? ' · ttl '.HtmlRenderer::esc((string) $payload['ttls'][$type]).'s' : '';
            foreach ($values as $value) {
                $lines[] = str_pad($type, 6).$esc($value).$ttl;
            }
        }

        if ($lines === []) {
            $status = $statuses['zone'] ?? ($statuses['A'] ?? null);
            $lines[] = $status === 'NXDOMAIN'
                ? 'Zone does not exist (NXDOMAIN). Check spelling?'
                : 'No records answered.';
        }

        $sections = [new Section('', $lines, monospace: true)];

        $notes = self::notes($payload, $statuses);
        if ($notes !== []) {
            $sections[] = new Section('', array_map(static fn (string $n): string => 'ℹ️ '.$esc($n), $notes));
        }

        /** @var list<string> $degraded */
        $degraded = array_values(array_filter(array_map(strval(...), (array) ($result->degradedSources ?? []))));
        foreach ($degraded as $resolver) {
            $sections[] = new Section('', ['⚠️ Resolver '.$esc($resolver).' unavailable — showing partial results']);
        }

        $footer = (new Footer())->add((string) ($payload['source_host'] ?? 'dns'), $result->latencyMs);

        return [
            'text' => (new HtmlRenderer())->render('DNS · '.$esc($targetHost), $sections, $footer),
            'keyboard' => [MenuBackRow::row($chatId)],
        ];
    }

    /**
     * @param  array<string, mixed>  $payload
     * @param  array<string, string>  $statuses
     * @return list<string>
     */
    private static function notes(array $payload, array $statuses): array
    {
        $notes = [];

        if (($payload['dnssec_ad']) === true) {
            $notes[] = 'DNSSEC validation succeeded on the resolver side (AD bit)';
        }
        if ((bool) ($payload['authoritative'] ?? false)) {
            $notes[] = 'answered by an authoritative nameserver';
        }
        if (($statuses['SOA'] ?? '') === 'NOERROR' && ! isset($payload['records']['SOA'])) {
            $notes[] = 'SOA query answered without data — unusual zone state';
        }

        return $notes;
    }
}
