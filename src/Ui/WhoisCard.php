<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Support\HumanTime;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;

/**
 * Pure /whois card per the §3.3 mockup. Renders from the cached payload
 * tree only — actions re-render identical output from cache later.
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class WhoisCard
{
    public static function render(ProbeResult $result, int $chatId, int $now, string $targetHost): array
    {
        $esc = HtmlRenderer::esc(...);
        $payload = $result->payload;

        $summary = self::keyValueLines([
            'Registrar' => self::registrarLine($payload),
            'Created' => self::datedLine(HumanTime::ageSince(self::strOrNull($payload['created_at'] ?? null), $now), $payload['created_at'] ?? null),
            'Updated' => self::datedLine(HumanTime::ageSince(self::strOrNull($payload['updated_at'] ?? null), $now), $payload['updated_at'] ?? null),
            'Expires' => self::expiresLine($payload, $now),
            'Status' => implode(', ', array_map($esc, self::listOf($payload, 'statuses'))),
            'Nameservers' => implode(', ', array_map($esc, self::listOf($payload, 'nameservers'))),
            'Contacts' => self::contactsLine($payload),
            'DNSSEC' => self::dnssecLine($payload),
        ]);

        $sections = [new Section('', $summary, monospace: true)];

        foreach ([...self::listOf($payload, 'redacted_fields'), (string) ($payload['hints']['homograph'] ?? '')] as $note) {
            if ($note !== '') {
                $sections[] = new Section('', ['⚠️ '.$esc($note)]);
            }
        }

        foreach (self::listOf($payload, 'degraded') as $degraded) {
            $sections[] = new Section('', ['⚠️ Source '.$esc($degraded).' unavailable — showing partial results']);
        }

        $footer = (new Footer())
            ->add((string) ($payload['source_host'] ?? 'whois'), $result->latencyMs);

        return [
            'text' => (new HtmlRenderer())->render('WHOIS · '.$esc($targetHost), $sections, $footer),
            'keyboard' => [MenuBackRow::row($chatId)],
        ];
    }

    /**
     * @param  array<string, string|null>  $map  label → rendered value
     * @return list<string>
     */
    private static function keyValueLines(array $map): array
    {
        $lines = [];
        $width = max(array_map(mb_strlen(...), array_keys($map))) + 1;

        foreach ($map as $label => $value) {
            if ($value === null || $value === '') {
                continue;
            }
            $lines[] = str_pad($label.':', $width).' '.$value;
        }

        return $lines === [] ? ['No whois data available.'] : $lines;
    }

    /** @param array<string, mixed> $payload */
    private static function registrarLine(array $payload): ?string
    {
        $name = HtmlRenderer::esc(self::strOrNull($payload['registrar_name'] ?? null) ?? 'unknown');
        $ianaId = self::strOrNull($payload['registrar_iana_id'] ?? null);

        return $ianaId !== null ? $name.' (IANA ID: '.HtmlRenderer::esc($ianaId).')' : $name;
    }

    private static function datedLine(?string $humanized, mixed $raw): ?string
    {
        if ($raw === null && $humanized === null) {
            return null;
        }
        $date = HtmlRenderer::esc(is_string($raw) ? substr($raw, 0, 10) : '?');

        return $humanized === null ? $date : $date.' ('.HtmlRenderer::esc($humanized).')';
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private static function expiresLine(array $payload, int $now): ?string
    {
        $expiresAt = self::strOrNull($payload['expires_at'] ?? null);
        if ($expiresAt === null) {
            return null;
        }

        $line = HtmlRenderer::esc(substr($expiresAt, 0, 10));
        $info = HumanTime::expiryInfo($expiresAt, $now);

        if ($info !== null) {
            if ($info['expired']) {
                $line .= ' — <b>expired ❌</b>';
            } elseif ($info['soon']) {
                $line .= ' — <b>in '.$info['days'].'d ⚠️</b>';
            } else {
                $countdown = HumanTime::countdownTo($expiresAt, $now);
                $line .= $countdown !== null ? ' — '.HtmlRenderer::esc($countdown).' ✅' : '';
            }
        }

        return $line;
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private static function contactsLine(array $payload): ?string
    {
        $parts = [];
        $org = self::strOrNull($payload['registrant_org'] ?? null);
        $abuse = self::strOrNull($payload['abuse_email'] ?? null);

        if ($org !== null) {
            $parts[] = 'registrant/org: '.HtmlRenderer::esc($org);
        }
        if ($abuse !== null) {
            $parts[] = 'abuse: '.HtmlRenderer::esc($abuse);
        }

        return $parts === [] ? null : implode(', ', $parts);
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private static function dnssecLine(array $payload): ?string
    {
        $dnssec = $payload['dnssec'] ?? null;

        return match (true) {
            $dnssec === true => 'signedDelegation ✅',
            $dnssec === false => 'unsigned ℹ️',
            default => null,
        };
    }

    /**
     * @param  array<string, mixed>  $payload
     * @return list<string>
     */
    private static function listOf(array $payload, string $key): array
    {
        return array_values(array_filter(
            array_map(strval(...), (array) ($payload[$key] ?? [])),
            static fn (string $v): bool => $v !== '',
        ));
    }

    private static function strOrNull(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
