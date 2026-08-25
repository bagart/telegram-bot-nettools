<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;
use BAGArt\TelegramBotNettools\Contracts\SourceHttpContract;

/**
 * RDAP-first whois source (RFC §7.1, D3): IANA bootstrap map (24h cache,
 * longest public-suffix match) → registry RDAP → one rel="related" referral
 * for thin registries. IP targets go through the rdap.org redirector.
 */
final class RdapClient
{
    private const string BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

    private const string BOOTSTRAP_CACHE_KEY = 'tg-nettools:rdap:bootstrap';

    private const int BOOTSTRAP_TTL_SECONDS = 86400;

    private const string IP_REDIRECTOR = 'https://rdap.org/ip/';

    private const int REFERRAL_HOPS = 1;

    public function __construct(
        private readonly SourceHttpContract $http,
        private readonly OutboundCacheContract $cache,
    ) {
    }

    /**
     * @return array{data: array<string, mixed>, server: string}|null null =
     *                                                                unavailable (caller
     *                                                                degrades to port-43)
     */
    public function lookupDomain(string $host, int $timeoutSeconds): ?array
    {
        $base = $this->bootstrapBaseFor($host);
        if ($base === null) {
            return $this->viaRedirector('https://rdap.org/domain/'.$host, $timeoutSeconds);
        }

        return $this->fetchWithReferral(rtrim($base, '/').'/domain/'.$host, $timeoutSeconds);
    }

    /** @return array{data: array<string, mixed>, server: string}|null */
    public function lookupIp(string $ip, int $timeoutSeconds): ?array
    {
        return $this->viaRedirector(self::IP_REDIRECTOR.$ip, $timeoutSeconds);
    }

    /**
     * RDAP JSON → normalized scalar tree shared with the port-43 path.
     *
     * @param  array<string, mixed>  $rdap
     * @return array<string, mixed>
     */
    public static function normalize(array $rdap): array
    {
        $registrar = self::entityByRole($rdap, 'registrar');
        $registrant = self::entityByRole($rdap, 'registrant');
        $abuse = self::entityByRole($rdap, 'abuse');

        $fields = [
            'registrar_name' => self::vcardValue($registrar, 'fn'),
            'registrar_iana_id' => self::ianaId($registrar),
            'created_at' => self::eventDate($rdap, 'registration'),
            'updated_at' => self::eventDate($rdap, 'last changed')
                ?? self::eventDate($rdap, 'last update of RDAP database'),
            'expires_at' => self::eventDate($rdap, 'expiration'),
            'statuses' => array_values(array_map(strval(...), (array) ($rdap['status'] ?? []))),
            'nameservers' => self::nameservers($rdap),
            'dnssec' => isset($rdap['secureDNS']['delegationSigned'])
                ? (bool) $rdap['secureDNS']['delegationSigned']
                : null,
            'registrant_org' => self::vcardValue($registrant, 'org') ?? self::vcardValue($registrant, 'fn'),
            'abuse_email' => self::vcardValue($abuse, 'email'),
            'redacted_fields' => self::redactedFields($rdap, $registrant, $abuse),
        ];

        return array_filter($fields, static fn (mixed $v): bool => $v !== null && $v !== []);
    }

    /**
     * Longest-suffix match over the bootstrap keys ("co.uk" beats "uk").
     */
    private function bootstrapBaseFor(string $host): ?string
    {
        foreach ($this->bootstrapMap() as $suffix => $urls) {
            if ($suffix === $host || str_ends_with($host, '.'.$suffix)) {
                $url = $urls[0] ?? null;

                return is_string($url) && $url !== '' ? $url : null;
            }
        }

        return null;
    }

    /** @return array<string, list<string>> tld suffix → RDAP base URLs */
    private function bootstrapMap(): array
    {
        $cached = $this->cache->get(self::BOOTSTRAP_CACHE_KEY);
        if (is_string($cached) && $cached !== '') {
            try {
                /** @var mixed $decoded */
                $decoded = json_decode($cached, true, 8, JSON_THROW_ON_ERROR);
                if (is_array($decoded) && $decoded !== []) {
                    /** @var array<string, list<string>> */
                    return $decoded;
                }
            } catch (\JsonException) {
                // stale/corrupt entry — refresh below
            }
        }

        $document = $this->http->getJson(self::BOOTSTRAP_URL, 5);
        $map = [];
        if ($document !== null) {
            foreach ((array) ($document['services'] ?? []) as $service) {
                if (! is_array($service) || count($service) < 2) {
                    continue;
                }
                foreach ((array) $service[0] as $tld) {
                    $map[(string) strtolower($tld)] = array_values(array_map(
                        strval(...),
                        array_filter((array) $service[1], static fn (mixed $u): bool => is_string($u)),
                    ));
                }
            }
        }

        if ($map !== []) {
            $this->cache->put(
                self::BOOTSTRAP_CACHE_KEY,
                json_encode($map, JSON_THROW_ON_ERROR),
                self::BOOTSTRAP_TTL_SECONDS,
            );

            return $map;
        }

        return []; // bootstrap down → redirector fallback per lookupDomain()
    }

    /** @return array{data: array<string, mixed>, server: string}|null */
    private function viaRedirector(string $url, int $timeoutSeconds): ?array
    {
        $data = $this->http->getJson($url, $timeoutSeconds);

        return $data === null ? null : ['data' => $data, 'server' => (string) parse_url($url, PHP_URL_HOST)];
    }

    /**
     * Thin registries answer with links[] rel="related" pointing at the
     * registrar RDAP — followed exactly once (Appendix B).
     *
     * @return array{data: array<string, mixed>, server: string}|null
     */
    private function fetchWithReferral(string $url, int $timeoutSeconds): ?array
    {
        $data = $this->http->getJson($url, $timeoutSeconds);
        if ($data === null) {
            return null;
        }

        $server = (string) parse_url($url, PHP_URL_HOST);

        for ($hop = 0; $hop < self::REFERRAL_HOPS; $hop++) {
            $related = self::relatedHref($data);
            if ($related === null || $related === $url) {
                break;
            }

            $referred = $this->http->getJson($related, $timeoutSeconds);
            if ($referred === null) {
                break; // keep the thin registry answer rather than fail
            }

            $data = $referred;
            $url = $related;
            $server = (string) parse_url($related, PHP_URL_HOST);
        }

        return ['data' => $data, 'server' => $server];
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private static function relatedHref(array $data): ?string
    {
        foreach ((array) ($data['links'] ?? []) as $link) {
            if (! is_array($link)) {
                continue;
            }
            if (strtolower((string) ($link['rel'] ?? '')) === 'related'
                && str_starts_with((string) ($link['href'] ?? ''), 'https://')
            ) {
                return (string) $link['href'];
            }
        }

        return null;
    }

    /**
     * @param  array<string, mixed>  $rdap
     */
    private static function entityByRole(array $rdap, string $role): ?array
    {
        foreach ((array) ($rdap['entities'] ?? []) as $entity) {
            if (is_array($entity) && in_array($role, array_map(strval(...), (array) ($entity['roles'] ?? [])), true)) {
                return $entity;
            }
        }

        return null;
    }

    /**
     * vCard value by key: vcardArray[1] entries look like ["email", {}, "text", "abuse@…"].
     *
     * @param  array<string, mixed>|null  $entity
     */
    private static function vcardValue(?array $entity, string $key): ?string
    {
        $vcard = $entity['vcardArray'][1] ?? null;
        if (! is_array($vcard)) {
            return null;
        }

        foreach ($vcard as $entry) {
            if (is_array($entry) && count($entry) >= 4
                && strtolower((string) $entry[0]) === $key
                && is_scalar($entry[3]) && (string) $entry[3] !== ''
            ) {
                return (string) $entry[3];
            }
        }

        return null;
    }

    /**
     * @param  array<string, mixed>|null  $entity
     */
    private static function ianaId(?array $entity): ?string
    {
        if ($entity === null) {
            return null;
        }

        foreach ((array) ($entity['publicIds'] ?? []) as $publicId) {
            if (is_array($publicId)
                && stripos((string) ($publicId['type'] ?? ''), 'IANA') !== false
                && (string) ($publicId['identifier'] ?? '') !== ''
            ) {
                return preg_replace('/\D/', '', (string) $publicId['identifier']) ?: null;
            }
        }

        return null;
    }

    /**
     * @param  array<string, mixed>  $rdap
     */
    private static function eventDate(array $rdap, string $action): ?string
    {
        foreach ((array) ($rdap['events'] ?? []) as $event) {
            if (is_array($event)
                && strtolower((string) ($event['eventAction'] ?? '')) === $action
                && preg_match('/\d{4}-\d{2}-\d{2}/', (string) ($event['eventDate'] ?? ''), $m)
            ) {
                return $m[0];
            }
        }

        return null;
    }

    /**
     * @param  array<string, mixed>  $rdap
     * @return list<string>
     */
    private static function nameservers(array $rdap): array
    {
        $nameservers = [];
        foreach ((array) ($rdap['nameservers'] ?? []) as $nameserver) {
            if (is_array($nameserver) && isset($nameserver['ldhName'])) {
                $nameservers[] = strtolower((string) $nameserver['ldhName']);
            }
        }

        return $nameservers;
    }

    /**
     * GDPR-era redaction markers (Appendix B): explicit remarks on entities
     * plus implicit "role present, value absent".
     *
     * @param  array<string, mixed>|null  $registrant
     * @param  array<string, mixed>|null  $abuse
     * @return list<string>
     */
    private static function redactedFields(array $rdap, ?array $registrant, ?array $abuse): array
    {
        $redacted = [];

        foreach ([$registrant, $abuse] as $entity) {
            if ($entity === null) {
                continue;
            }
            foreach ((array) ($entity['remarks'] ?? []) as $remark) {
                if (! is_array($remark)) {
                    continue;
                }
                $description = implode(' ', array_map(strval(...), (array) ($remark['description'] ?? [])));
                if (stripos((string) ($remark['title'] ?? '').$description, 'REDACTED') !== false) {
                    $redacted[] = (string) ($remark['title'] ?? 'field');
                }
            }
        }

        if ($registrant !== null && self::vcardValue($registrant, 'fn') === null
            && self::vcardValue($registrant, 'org') === null
        ) {
            $redacted[] = 'registrant identity';
        }

        if ($abuse !== null && self::vcardValue($abuse, 'email') === null) {
            $redacted[] = 'abuse contact';
        }

        return array_values(array_unique($redacted));
    }
}
