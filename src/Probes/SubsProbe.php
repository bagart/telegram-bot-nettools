<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Sources\CtLogSource;
use BAGArt\TelegramBotNettools\Sources\DnsAnswer;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Support\SubdomainWordlist;

/**
 * /subs subdomain enumeration (RFC §7.6): wildcard detection FIRST, then
 * passive CT logs (crt.sh → certspotter fallback), then opt-in wordlist
 * brute-force, then A/AAAA resolution of the top slice with a DNS-only
 * takeover-risk HINT pass. Every stage degrades independently — an empty
 * result is a valid outcome, never an exception.
 */
final class SubsProbe implements NettoolsProbeContract
{
    public const string FLAG_BRUTE = 'brute';

    private const int BRUTE_LABEL_CAP = 3000;

    private const int RESOLVE_QUERY_CAP = 220;

    private const int CERTSPOTTER_FALLBACK_BELOW = 5;

    /** @var list<string> */
    private const array TAKEOVER_FINGERPRINTS = [
        's3.amazonaws.com',
        'github.io',
        'herokuapp.com',
        'azurewebsites.net',
        'cloudfront.net',
        'fastly.net',
        'myshopify.com',
        'tumblr.com',
    ];

    /**
     * @param  list<string>  $resolvers  resolver IPs (first one drives brute)
     * @param  \Closure|null  $progress  optional fn(string $stage): void
     * @param  list<string>|null  $wordlistOverride  replaces the bundled
     *                                            default labels for the brute stage
     */
    public function __construct(
        private readonly CtLogSource $ct,
        private readonly DnsClient $dns,
        private readonly array $resolvers,
        private readonly int $timeoutSeconds = 3,
        private readonly int $maxShow = 200,
        private readonly bool $bruteEnabled = false,
        private readonly ?\Closure $progress = null,
        private readonly ?array $wordlistOverride = null,
    ) {
    }

    public function name(): string
    {
        return 'subs';
    }

    public function ttlSeconds(): int
    {
        return 43200;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        $host = $target->host;
        $timeout = max(1, $this->timeoutSeconds);

        $this->advance('wildcard');
        $wildcard = $this->detectWildcard($host, $timeout);

        $this->advance('passive');
        $names = [];
        [$okSources, $degraded, $sourceCounts] = $this->passiveCollect($host, $timeout, $names);

        $bruteQueried = 0;
        $bruteResolved = 0;
        $knownIps = [];
        $bruteNameSet = [];

        if ($this->bruteEnabled || $options->flag(self::FLAG_BRUTE)) {
            $this->advance('brute');
            [$bruteNames, $bruteQueried, $bruteResolved, $knownIps] = $this->brute($host, $timeout);
            foreach ($bruteNames as $name) {
                $names[$name] = true;
                $bruteNameSet[$name] = true;
            }
        }

        $sorted = array_keys($names);
        sort($sorted, SORT_STRING);

        $this->advance('resolve');
        [$rows, $ctOnly] = $this->resolveTop($sorted, $knownIps, $timeout);

        $suspectTakeover = [];
        foreach ($rows as $index => $row) {
            if ($wildcard && isset($bruteNameSet[$row['name']])) {
                $rows[$index]['suspect'] ??= 'wildcard-zone';
            }
            $provider = $row['cname'] !== null ? self::takeoverProvider($row['cname']) : null;
            if ($provider !== null) {
                $rows[$index]['suspect'] = $provider;
                $suspectTakeover[] = ['name' => $row['name'], 'provider' => $provider];
            }
        }

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: 0,
            degradedSources: $degraded,
            payload: [
                'host' => $host,
                'wildcard' => $wildcard,
                'resolved' => $rows,
                'ct_only' => $ctOnly,
                'counts' => [
                    'ct' => count($sourceCounts) > 0 ? array_sum($sourceCounts) : 0,
                    'brute_resolved' => $bruteResolved,
                    'brute_queried' => $bruteQueried,
                ],
                'sources' => $okSources,
                'source_counts' => $sourceCounts,
                'suspect_takeover' => $suspectTakeover,
                'truncated' => $ctOnly !== [],
            ],
        );
    }

    /**
     * Both random labels resolving ⇒ wildcard zone; brute rows become
     * wildcard-suspect while CT results stay unaffected.
     */
    private function detectWildcard(string $host, int $timeout): bool
    {
        if ($this->resolvers === []) {
            return false;
        }

        $answered = 0;
        foreach (['ntwc-'.bin2hex(random_bytes(8)), 'ntwd-'.bin2hex(random_bytes(8))] as $label) {
            foreach ($this->resolvers as $resolver) {
                $answer = $this->dns->query($resolver, $label.'.'.$host, 'A', $timeout);
                if ($answer !== null && ($answer->records['A'] ?? []) !== []) {
                    $answered++;

                    break;
                }
            }
        }

        return $answered === 2;
    }

    /**
     * crt.sh first; certspotter only when crt.sh is dead or thin. Fills
     * $names (unique set) and returns source bookkeeping.
     *
     * @param  array<string, true>  $names
     * @return array{0: list<string>, 1: list<string>, 2: array<string, int>}
     */
    private function passiveCollect(string $host, int $timeout, array &$names): array
    {
        $ok = [];
        $degraded = [];
        $sourceCounts = [];

        $crtsh = $this->ct->fetchCrtsh($host, $timeout);
        if ($crtsh === null) {
            $degraded[] = CtLogSource::NAME_CRTSH;
        } else {
            foreach ($crtsh as $name) {
                $names[$name] = true;
            }
            $ok[] = CtLogSource::NAME_CRTSH;
            $sourceCounts[CtLogSource::NAME_CRTSH] = count($crtsh);
        }

        if ($crtsh === null || count($names) < self::CERTSPOTTER_FALLBACK_BELOW) {
            $certspotter = $this->ct->fetchCertspotter($host, $timeout);
            if ($certspotter === null) {
                $degraded[] = CtLogSource::NAME_CERTSPOTTER;
            } else {
                $before = count($names);
                foreach ($certspotter as $name) {
                    $names[$name] = true;
                }
                $ok[] = CtLogSource::NAME_CERTSPOTTER;
                $sourceCounts[CtLogSource::NAME_CERTSPOTTER] = count($names) - $before;
            }
        }

        return [$ok, $degraded, $sourceCounts];
    }

    /**
     * Wordlist A-sweep against the first resolver. Returns the resolved
     * full names plus their discovered addresses (reused by the resolve
     * stage so brute hits survive resolver flakiness).
     *
     * @return array{0: list<string>, 1: int, 2: int, 3: array<string, list<string>>}
     */
    private function brute(string $host, int $timeout): array
    {
        $resolver = $this->resolvers[0] ?? null;
        if ($resolver === null) {
            return [[], 0, 0, []];
        }

        /** @var list<string> $labels */
        $labels = array_values(array_unique(
            $this->wordlistOverride ?? SubdomainWordlist::$DEFAULT,
        ));
        $labels = array_slice($labels, 0, self::BRUTE_LABEL_CAP);

        $found = [];
        $knownIps = [];
        $queried = 0;
        $resolved = 0;

        foreach ($labels as $label) {
            $answer = $this->dns->query($resolver, $label.'.'.$host, 'A', $timeout);
            $queried++;

            $ips = $answer?->records['A'] ?? null;
            if ($ips === null || $ips === []) {
                continue;
            }

            $name = $label.'.'.$host;
            $found[] = $name;
            $knownIps[$name] = array_values(array_unique($ips));
            $resolved++;
        }

        return [$found, $queried, $resolved, $knownIps];
    }

    /**
     * A/AAAA pass over the alphabetically-first slice within the query cap;
     * everything beyond the attempt window is reported as ct_only. Brute-
     * discovered addresses are merged in as the baseline.
     *
     * @param  list<string>  $names  sorted
     * @param  array<string, list<string>>  $knownIps
     * @return array{0: list<array{name: string, ips: list<string>, cname: ?string, suspect: ?string}>, 1: list<string>}
     */
    private function resolveTop(array $names, array $knownIps, int $timeout): array
    {
        $resolver = $this->resolvers[0] ?? null;
        $rows = [];
        $budget = self::RESOLVE_QUERY_CAP;

        foreach ($names as $index => $name) {
            if ($index >= $this->maxShow || $resolver === null || $budget < 1) {
                return [$rows, array_slice($names, $index)];
            }

            $ips = $knownIps[$name] ?? [];
            $cname = null;

            $a = $this->dns->query($resolver, $name, 'A', $timeout);
            $budget--;
            $cname ??= self::firstCname($a);
            foreach ($a?->records['A'] ?? [] as $ip) {
                $ips[] = $ip;
            }

            if ($budget >= 1) {
                $aaaa = $this->dns->query($resolver, $name, 'AAAA', $timeout);
                $budget--;
                $cname ??= self::firstCname($aaaa);
                foreach ($aaaa?->records['AAAA'] ?? [] as $ip) {
                    $ips[] = $ip;
                }
            }

            $rows[] = [
                'name' => $name,
                'ips' => array_values(array_unique($ips)),
                'cname' => $cname,
                'suspect' => null,
            ];
        }

        return [$rows, []];
    }

    private static function firstCname(?DnsAnswer $answer): ?string
    {
        $records = $answer?->records['CNAME'] ?? [];

        return $records[0] ?? null;
    }

    /** CNAME target → takeover provider fingerprint, null when unknown. */
    private static function takeoverProvider(string $cname): ?string
    {
        foreach (self::TAKEOVER_FINGERPRINTS as $fingerprint) {
            if ($cname === $fingerprint || str_ends_with($cname, '.'.$fingerprint)) {
                return $fingerprint;
            }
        }

        return null;
    }

    private function advance(string $stage): void
    {
        if ($this->progress !== null) {
            ($this->progress)($stage);
        }
    }
}
