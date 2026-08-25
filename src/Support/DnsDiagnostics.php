<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBotNettools\Sources\DnsClient;

/**
 * /dns advanced diagnostics (RFC §7.2): multi-resolver propagation diff,
 * lame-delegation and open-recursion checks over the zone's own NS set.
 */
final class DnsDiagnostics
{
    private const array PUBLIC_RESOLVERS = ['9.9.9.9', '208.67.222.222'];

    /** @param list<string> $resolvers configured module resolvers */
    public function __construct(
        private readonly DnsClient $dns,
        private readonly array $resolvers,
    ) {
    }

    /**
     * @return array{host:string, rows:list<array{resolver:string, kind:string, value:?string, ttl:?int}>, divergent:bool, authoritative:list<string>}
     */
    public function propagation(string $host): array
    {
        $servers = [...array_unique($this->resolvers), ...self::PUBLIC_RESOLVERS];
        $rows = [];
        $answersByKind = ['A' => [], 'AAAA' => []];
        $authoritative = [];

        foreach ($servers as $server) {
            foreach (array_keys($answersByKind) as $kind) {
                $answer = $this->dns->query($server, $host, $kind, 2);
                $value = $answer === null || ($answer->records[$kind][0] ?? null) === null
                    ? null
                    : (string) $answer->records[$kind][0];

                $rows[] = [
                    'resolver' => $server,
                    'kind' => $kind,
                    'value' => $value,
                    'ttl' => $answer === null ? null : (($answer->ttls[$kind][0] ?? null)),
                ];

                if ($kind === 'A') {
                    $answersByKind[$kind][] = $value ?? '—';
                }
                if ($answer !== null && $answer->authoritative) {
                    $authoritative[] = $server;
                }
            }
        }

        $uniqueA = array_unique($answersByKind['A']);

        return [
            'host' => $host,
            'rows' => $rows,
            'divergent' => count($uniqueA) > 1,
            'authoritative' => array_values(array_unique($authoritative)),
        ];
    }

    /**
     * Lame delegation (NS does not answer authoritatively for the zone) +
     * open-recursion check (zone NS resolves third-party names).
     *
     * @return array{host:string, ns_rows:list<array{ns:string, ip:?string, authoritative:bool, open_resolver:?bool}>, lame:list<string>}
     */
    public function lameAndOpen(string $host): array
    {
        $primary = $this->resolvers[0] ?? '1.1.1.1';
        $nsAnswer = $this->dns->query($primary, $host, 'NS', 2);
        $nameservers = $nsAnswer === null ? [] : array_map(strval(...), (array) ($nsAnswer->records['NS'] ?? []));

        $rows = [];
        $lame = [];

        foreach (array_slice($nameservers, 0, 6) as $ns) {
            $nsIp = $this->firstA($primary, $ns);

            $soaAtNs = $nsIp === null ? null : $this->dns->query($nsIp, $host, 'SOA', 2);
            $authoritativeForZone = $soaAtNs !== null && $soaAtNs->authoritative;

            // third-party name with recursion desired: an ANSWER means world recursion
            $openProbe = $nsIp === null
                ? null
                : $this->dns->query($nsIp, 'open-resolver-probe.ntools.invalid', 'A', 2);
            $openResolver = $openProbe === null ? null : ($openProbe->records !== [] || $openProbe->rcode === 3 && ! $openProbe->authoritative);

            if (! $authoritativeForZone) {
                $lame[] = (string) $ns;
            }

            $rows[] = [
                'ns' => (string) $ns,
                'ip' => $nsIp,
                'authoritative' => $authoritativeForZone,
                'open_resolver' => $openResolver,
            ];
        }

        return ['host' => $host, 'ns_rows' => $rows, 'lame' => $lame];
    }

    private function firstA(string $from, string $host): ?string
    {
        $answer = $this->dns->query($from, rtrim($host, '.'), 'A', 2);
        $record = $answer?->records['A'][0] ?? null;

        return is_string($record) ? $record : null;
    }
}
