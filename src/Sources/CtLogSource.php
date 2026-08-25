<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

use BAGArt\TelegramBotNettools\Contracts\SourceHttpContract;

/**
 * Passive certificate-transparency sources (RFC §7.6): crt.sh JSON first,
 * certspotter as fallback. Both return null on missing body — a degraded
 * upstream signal, never an exception path.
 */
final class CtLogSource
{
    public const string NAME_CRTSH = 'crt.sh';

    public const string NAME_CERTSPOTTER = 'certspotter';

    public function __construct(private readonly SourceHttpContract $http)
    {
    }

    /**
     * Domain → unique subdomain names from crt.sh log entries.
     *
     * @return list<string>|null null = upstream unavailable
     */
    public function fetchCrtsh(string $domain, int $timeoutSeconds): ?array
    {
        $url = 'https://crt.sh/?q=%25.'.rawurlencode($domain).'&output=json';
        $body = $this->http->getJson($url, $timeoutSeconds);

        if ($body === null) {
            return null;
        }

        $names = [];
        foreach ($body as $entry) {
            $value = is_array($entry) ? ($entry['name_value'] ?? null) : null;
            if (! is_string($value)) {
                continue;
            }
            foreach (preg_split('/\r?\n/', $value) ?: [] as $name) {
                $names[] = $name;
            }
        }

        return self::normalize($names, $domain);
    }

    /**
     * Domain → unique subdomain names from certspotter issuances.
     *
     * @return list<string>|null null = upstream unavailable
     */
    public function fetchCertspotter(string $domain, int $timeoutSeconds): ?array
    {
        $url = 'https://api.certspotter.com/v1/issuances?domain='.rawurlencode($domain).'&include_subdomains=true&expand=dns_names';
        $body = $this->http->getJson($url, $timeoutSeconds);

        if ($body === null) {
            return null;
        }

        $names = [];
        foreach ($body as $entry) {
            $dnsNames = is_array($entry) ? ($entry['dns_names'] ?? null) : null;
            if (! is_array($dnsNames)) {
                continue;
            }
            foreach ($dnsNames as $name) {
                if (is_string($name)) {
                    $names[] = $name;
                }
            }
        }

        return self::normalize($names, $domain);
    }

    /**
     * Lowercase, strip '*.' prefixes, drop leftover wildcard labels, keep
     * only the target domain itself or its suffix matches, dedupe + sort.
     *
     * @param  list<string>  $raw
     * @return list<string>
     */
    private static function normalize(array $raw, string $domain): array
    {
        $domain = strtolower($domain);
        $suffix = '.'.$domain;
        $names = [];

        foreach ($raw as $name) {
            $name = strtolower(trim($name));
            if ($name === '') {
                continue;
            }
            if (str_starts_with($name, '*.')) {
                $name = substr($name, 2);
            }
            if (str_contains($name, '*')) {
                continue;
            }
            if ($name !== $domain && ! str_ends_with($name, $suffix)) {
                continue;
            }
            $names[] = $name;
        }

        $unique = array_values(array_unique($names));
        sort($unique, SORT_STRING);

        return $unique;
    }
}
