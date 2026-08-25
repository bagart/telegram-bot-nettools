<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

/**
 * Pure parsing helpers for mail-audit records (RFC 7208 / RFC 7489).
 * Static state only — the probe classifies records by name and feeds
 * single records here; multiple-SPF detection stays in the probe.
 */
final class MailRecordsParser
{
    /** DNS-consuming SPF terms per RFC 7208 §4.6.4, limit 10 per evaluation. */
    public const int SPF_LOOKUP_LIMIT = 10;

    /**
     * Parses one SPF record and statically counts DNS-consuming terms:
     * include:, a, mx, ptr, exists: and redirect=.
     *
     * @return array{mechanisms: list<string>, lookups: int, redirect: ?string, errors: list<string>}
     */
    public static function parseSpf(string $record): array
    {
        $mechanisms = [];
        $errors = [];
        $lookups = 0;
        $redirect = null;

        $terms = preg_split('/\s+/', trim($record)) ?: [];
        $version = array_shift($terms) ?? '';

        if (strtolower($version) !== 'v=spf1') {
            $errors[] = "record does not start with 'v=spf1'";
        }

        foreach ($terms as $term) {
            if ($term === '') {
                continue;
            }

            $qualifier = '';
            if (str_contains('+-~?', $term[0])) {
                $qualifier = $term[0];
                $term = substr($term, 1);
            }

            if ($term === '') {
                $errors[] = 'empty mechanism term';

                continue;
            }

            $lower = strtolower($term);

            // Dual-CIDR forms (a/24, mx://64, a:host/24) consume a lookup too.
            if (self::isDnsConsuming($lower)) {
                $lookups++;
                $mechanisms[] = $qualifier.$term;

                continue;
            }

            if ($lower === 'all' || str_starts_with($lower, 'ip4:') || str_starts_with($lower, 'ip6:')) {
                $mechanisms[] = $qualifier.$term;

                continue;
            }

            if (str_starts_with($lower, 'redirect=')) {
                if ($redirect !== null) {
                    $errors[] = "duplicate 'redirect' modifier";
                }
                $redirect = substr($term, 9);
                $lookups++;

                continue;
            }

            if (str_starts_with($lower, 'exp=') || str_contains($term, '=')) {
                continue; // exp= or unknown modifier — ignored per RFC 7208 §6
            }

            $errors[] = "unknown mechanism '{$term}'";
        }

        return [
            'mechanisms' => $mechanisms,
            'lookups' => $lookups,
            'redirect' => $redirect,
            'errors' => array_values(array_unique($errors)),
        ];
    }

    /**
     * Grades one DMARC record; null/empty input is "absent", not an error —
     * absence grading happens in the probe.
     *
     * @return array{policy: 'none'|'quarantine'|'reject'|null, rua: bool, pct: ?int, errors: list<string>}
     */
    public static function gradeDmarc(?string $record): array
    {
        if ($record === null || trim($record) === '') {
            return ['policy' => null, 'rua' => false, 'pct' => null, 'errors' => []];
        }

        $trimmed = trim($record);
        if (preg_match('/^v\s*=\s*DMARC1\b/i', $trimmed) !== 1) {
            return ['policy' => null, 'rua' => false, 'pct' => null, 'errors' => ["record does not start with 'v=DMARC1'"]];
        }

        $tags = [];
        foreach (explode(';', $trimmed) as $part) {
            $pair = explode('=', trim($part), 2);
            if (count($pair) === 2 && trim($pair[0]) !== '') {
                $tags[strtolower(trim($pair[0]))] = trim($pair[1]);
            }
        }

        $errors = [];
        $policy = strtolower(trim($tags['p'] ?? ''));
        if (! in_array($policy, ['none', 'quarantine', 'reject'], true)) {
            $policy = null;
            $errors[] = "missing or invalid 'p' tag";
        }

        $rua = isset($tags['rua']) && trim($tags['rua']) !== '';

        $pct = null;
        if (array_key_exists('pct', $tags)) {
            if (preg_match('/^\d+$/', trim($tags['pct'])) === 1 && (int) trim($tags['pct']) <= 100) {
                $pct = (int) trim($tags['pct']);
            } else {
                $errors[] = "invalid 'pct' tag";
            }
        }

        return ['policy' => $policy, 'rua' => $rua, 'pct' => $pct, 'errors' => $errors];
    }

    private static function isDnsConsuming(string $lowerTerm): bool
    {
        if (str_starts_with($lowerTerm, 'include:') || str_starts_with($lowerTerm, 'exists:')) {
            return true;
        }

        foreach (['a', 'mx', 'ptr'] as $name) {
            if ($lowerTerm === $name || str_starts_with($lowerTerm, $name.':') || str_starts_with($lowerTerm, $name.'/')) {
                return true;
            }
        }

        return false;
    }
}
