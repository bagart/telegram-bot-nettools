<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

/**
 * Humanized date deltas for cards (RFC §3.3: "1995-08-31 (31.0y ago)",
 * "2026-08-30 — in 8 days ⚠️"). Tolerates RFC3339 and partial dates.
 */
final class HumanTime
{
    /** "31.0y ago" | "5.2mo ago" | "12d ago" */
    public static function ageSince(?string $date, int $now): ?string
    {
        $timestamp = self::parse($date);

        return $timestamp === null ? null : self::humanizeDelta($now - $timestamp).' ago';
    }

    /** "in 8 days ⚠️" | "in 3.1mo" | "2y ago" for past dates */
    public static function countdownTo(?string $date, int $now): ?string
    {
        $timestamp = self::parse($date);

        return $timestamp === null ? null : 'in '.self::humanizeDelta($timestamp - $now);
    }

    public static function expiresSoonDays(): int
    {
        return 14;
    }

    /**
     * @return array{days: int, soon: bool, expired: bool}|null
     */
    public static function expiryInfo(?string $date, int $now): ?array
    {
        $timestamp = self::parse($date);
        if ($timestamp === null) {
            return null;
        }

        $days = (int) floor(($timestamp - $now) / 86400);

        return [
            'days' => $days,
            'soon' => $days >= 0 && $days <= self::expiresSoonDays(),
            'expired' => $timestamp < $now,
        ];
    }

    private static function humanizeDelta(int $seconds): string
    {
        $past = $seconds < 0;
        $days = abs($seconds) / 86400;

        $value = match (true) {
            $days < 45 => number_format($days, 0).'d',
            $days < 365 * 2 => round($days / 30.44, 1).'mo',
            default => round($days / 365.25, 1).'y',
        };

        // Trim trailing ".0"
        if (str_contains($value, '.')) {
            $value = rtrim(rtrim($value, '0'), '.');
        }

        return ($past ? '-' : '').$value;
    }

    private static function parse(?string $date): ?int
    {
        if ($date === null || trim($date) === '') {
            return null;
        }

        $timestamp = strtotime(substr(trim($date), 0, 10));

        return $timestamp === false ? null : $timestamp;
    }
}
