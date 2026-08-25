<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

/**
 * Network-type classification from org/ISP naming heuristics (RFC §7.3).
 * Honest by construction: unknown stays unknown; the label is informational.
 */
final class AsnClassifier
{
    /** @var list<string> */
    private const array HOSTING = [
        'hosting', 'host ', 'cloud', 'vps', 'dedicated', 'datacenter', 'data center',
        'amazon', 'aws', 'google', 'microsoft', 'azure', 'oracle',
        'hetzner', 'ovh', 'digitalocean', 'linode', 'vultr', 'contabo', 'leaseweb',
        'scaleway', 'choose', 'selectel', 'timeweb', 'beget', 'sprinthost',
    ];

    /** @var list<string> */
    private const array EDUCATION = ['universit', 'university', 'univ ', ' edu', '.edu', 'academ', 'institut', 'school'];

    /** @var list<string> */
    private const array RESIDENTIAL = [
        'mobile', 'broadb', 'telecom', 'communications', 'comcast', 'verizon', 'at&t',
        'vodafone', 'orange', 'telefonica', 'deutsche telek', 'british telecom', 'bt ',
        'rostelecom', 'mts ', 'megafon', 'beeline', 'vimpelcom', 'ericsson',
        'residential', 'home ', 'fios', 'cable',
    ];

    public static function classify(?string ...$orgTexts): string
    {
        $haystack = mb_strtolower(implode(' ', array_filter($orgTexts)));

        if ($haystack === '') {
            return 'unknown';
        }

        foreach (self::EDUCATION as $needle) {
            if (str_contains($haystack, $needle)) {
                return 'education';
            }
        }

        foreach (self::HOSTING as $needle) {
            if (str_contains($haystack, $needle)) {
                return 'hosting/cloud';
            }
        }

        foreach (self::RESIDENTIAL as $needle) {
            if (str_contains($haystack, $needle)) {
                return 'residential/isp';
            }
        }

        return 'business/other';
    }

    public static function emoji(string $type): string
    {
        return match ($type) {
            'hosting/cloud' => '☁️',
            'education' => '🎓',
            'residential/isp' => '🏠',
            default => '🏢',
        };
    }
}
