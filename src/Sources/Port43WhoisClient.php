<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

/**
 * Port-43 whois client (RFC §7.1): small per-TLD server map, IANA referral
 * as the universal fallback, then one "Registrar WHOIS Server" deep query.
 * Returns the most specific answer found with its source server for the
 * card footer.
 */
final class Port43WhoisClient
{
    /** @var array<string, string> tld → whois server */
    private const array SERVER_MAP = [
        'com' => 'whois.verisign-grs.com',
        'net' => 'whois.verisign-grs.com',
        'org' => 'whois.publicinterestregistry.org',
        'info' => 'whois.identitydigital.services',
        'io' => 'whois.nic.io',
        'dev' => 'whois.nic.google',
        'app' => 'whois.nic.google',
        'page' => 'whois.nic.google',
        'xyz' => 'whois.nic.xyz',
        'ru' => 'whois.tcinet.ru',
        'su' => 'whois.tcinet.ru',
        'uk' => 'whois.nic.uk',
    ];

    private const string IANA_SERVER = 'whois.iana.org';

    public function __construct(private readonly Port43TransportContract $transport)
    {
    }

    /**
     * @return array{text: string, server: string}|null null = every hop
     *                                                  failed (caller renders
     *                                                  a degraded-source note)
     */
    public function lookup(string $host, int $timeoutSeconds): ?array
    {
        $server = self::SERVER_MAP[$this->tldOf($host)] ?? self::IANA_SERVER;

        $text = $this->transport->ask($server, $host, $timeoutSeconds);
        if ($text === null) {
            return null;
        }

        // IANA answers thin: refer to the registry server, then to the
        // registrar. Each hop replaces the previous answer when it succeeds.
        foreach ($this->referralServers($text) as $referral) {
            if ($referral === $server) {
                continue;
            }

            $deeper = $this->transport->ask($referral, $host, $timeoutSeconds);
            if ($deeper !== null) {
                $text = $deeper;
                $server = $referral;
            }

            break; // follow at most one explicit referral per level
        }

        return ['text' => $text, 'server' => $server];
    }

    /**
     * Normalized scalar tree from a port-43 text answer (subset of the RDAP
     * shape — the probe merges both into one payload).
     *
     * @return array<string, mixed>
     */
    public static function normalize(string $text): array
    {
        $fields = [
            'registrar_name' => null,
            'registrar_iana_id' => null,
            'created_at' => null,
            'updated_at' => null,
            'expires_at' => null,
            'statuses' => [],
            'nameservers' => [],
            'dnssec' => null,
            'registrant_org' => null,
            'abuse_email' => null,
            'redacted_fields' => [],
        ];

        foreach (explode("\n", $text) as $line) {
            [$key, $value] = array_pad(explode(':', $line, 2), 2, '');
            $key = trim($key);
            $value = trim($value);

            self::mapLine($fields, strtolower($key), rtrim($value, ';'));
        }

        return array_filter($fields, static fn (mixed $v): bool => $v !== null && $v !== []);
    }

    /** @param array<string, mixed> $fields */
    private static function mapLine(array &$fields, string $key, string $value): void
    {
        switch ($key) {
            case 'registrar':
                $fields['registrar_name'] ??= $value !== '' ? $value : null;
                break;
            case 'registrar iana id':
                $digits = $value !== '' ? preg_replace('/\D/', '', $value) : '';
                $fields['registrar_iana_id'] ??= $digits !== '' ? $digits : null;
                break;
            case 'creation date':
            case 'created date':
            case 'created on':
            case 'registered on':
                $fields['created_at'] ??= self::datePart($value);
                break;
            case 'updated date':
            case 'last updated on':
            case 'last modified':
                $fields['updated_at'] ??= self::datePart($value);
                break;
            case 'registry expiry date':
            case 'registrar registration expiration date':
            case 'expiry date':
            case 'expiration date':
            case 'paid-till date':
                $fields['expires_at'] ??= self::datePart($value);
                break;
            case 'domain status':
            case 'status':
                if ($value !== '') {
                    $fields['statuses'][] = explode(' ', $value)[0];
                }
                break;
            case 'name server':
            case 'name servers':
                if ($value !== '') {
                    $fields['nameservers'][] = strtolower(explode(' ', $value)[0]);
                }
                break;
            case 'dnssec':
                $normalized = strtolower($value);
                $fields['dnssec'] = in_array($normalized, ['signeddelegation', 'yes', 'true'], true)
                    ? true
                    : (in_array($normalized, ['unsigned', 'no', 'false'], true) ? false : null);
                break;
        }
    }

    private static function datePart(string $value): ?string
    {
        if ($value === '' || ! preg_match('/\d{4}-\d{2}-\d{2}/', $value, $m)) {
            return null;
        }

        return $m[0];
    }

    /**
     * @return list<string> referral servers declared in a thin answer
     */
    private function referralServers(string $text): array
    {
        if (! preg_match_all('/^(?:Registrar |Registry )?WHOIS Server:\s*(\S+)/im', $text, $matches)) {
            return [];
        }

        return array_values(array_unique($matches[1]));
    }

    private function tldOf(string $host): string
    {
        $parts = explode('.', $host);

        return count($parts) < 2 ? '' : strtolower((string) end($parts));
    }
}
