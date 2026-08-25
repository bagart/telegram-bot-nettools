<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\MmdbContract;
use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Sources\IpApiSource;
use BAGArt\TelegramBotNettools\Sources\RipestatSource;
use BAGArt\TelegramBotNettools\Support\AsnClassifier;
use BAGArt\TelegramBotNettools\Support\SourceBreaker;

/**
 * /ip geo+ASN probe (RFC §7.3): mmdb → ip-api.com → RIPEstat fallback chain,
 * rDNS PTR with forward-confirmation, network-type classification, honest v6
 * reachability note from this server. Reserved/labeled ranges are never geo'd.
 */
final class GeoAsnProbe implements NettoolsProbeContract
{
    public function __construct(
        private readonly IpApiSource $ipApi,
        private readonly RipestatSource $ripestat,
        private readonly DnsClient $dns,
        private readonly array $resolvers,
        private readonly ?MmdbContract $mmdb = null,
        private readonly ?SourceBreaker $breaker = null,
        /** @var (Closure(string $ip, int $timeoutSeconds): bool)|null TCP :443 reachability seam */
        private readonly ?\Closure $v6Probe = null,
    ) {
    }

    public function name(): string
    {
        return 'ip';
    }

    public function ttlSeconds(): int
    {
        return 86400;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        $ip = $target->ips[0] ?? null;

        $payload = [
            'ip' => $ip,
            'reserved' => $target->verdict->label,
            'country' => null,
            'region' => null,
            'city' => null,
            'lat' => null,
            'lon' => null,
            'asn' => null,
            'asn_org' => null,
            'org' => null,
            'type' => 'unknown',
            'ptr' => null,
            'ptr_confirmed' => null,
            'v6_reach' => null,
            'rpki' => null,
            'source' => [],
        ];
        $degraded = [];

        if ($target->verdict->label === null) {
            $this->geoAndAsn($target, $payload, $degraded);
        }

        if ($ip !== null && $payload['asn'] !== null && $payload['rpki'] === null) {
            $roa = $this->viaBreaker(RipestatSource::NAME, $degraded, fn (): ?array => [
                'status' => $this->ripestat->rpkiFor($ip),
            ]);
            if (is_array($roa) && is_string($roa['status'] ?? null)) {
                $payload['rpki'] = $roa['status'];
            }
        }

        $this->reverseDns($target, $payload, $degraded);
        $this->v6Reachability($target, $payload);

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: 0,
            degradedSources: $degraded,
            payload: $payload,
        );
    }

    /**
     * @param  array<string, mixed>  $payload
     * @param  list<string>  $degraded
     */
    private function geoAndAsn(NetTarget $target, array &$payload, array &$degraded): void
    {
        $ip = $target->ips[0];

        // Local mmdb first — 0ms, no egress, no rate limits
        if ($this->mmdb !== null) {
            $geo = $this->mmdb->city($ip);
            $asn = $this->mmdb->asn($ip);
            if ($geo !== null) {
                $payload['source'][] = 'mmdb';
                $payload['country'] = $geo['country'];
                $payload['region'] = $geo['region'];
                $payload['city'] = $geo['city'];
                $payload['lat'] = $geo['lat'];
                $payload['lon'] = $geo['lon'];
            }
            if ($asn !== null) {
                $payload['source'][] = 'mmdb';
                $payload['asn'] = $asn['asn'];
                $payload['asn_org'] = $asn['org'];
                $payload['org'] = $asn['org'];
            }
            if ($geo === null && $asn === null) {
                $degraded[] = 'mmdb';
            }
        }

        $apiGeo = $this->viaBreaker(IpApiSource::NAME, $degraded, fn (): ?array => $this->ipApi->fetch($ip));
        if ($apiGeo !== null) {
            $payload['source'][] = IpApiSource::NAME;

            if ($payload['country'] === null) {
                $payload['country'] = self::str($apiGeo['country'] ?? null);
            }
            if ($payload['region'] === null) {
                $payload['region'] = self::str($apiGeo['regionName'] ?? null);
            }
            if ($payload['city'] === null) {
                $payload['city'] = self::str($apiGeo['city'] ?? null);
            }
            if ($payload['lat'] === null) {
                $payload['lat'] = round((float) ($apiGeo['lat'] ?? 0), 2) ?: null;
            }
            if ($payload['lon'] === null) {
                $payload['lon'] = round((float) ($apiGeo['lon'] ?? 0), 2) ?: null;
            }

            $asText = self::str($apiGeo['as'] ?? null); // "AS15169 GOOGLE, US"
            if ($payload['asn'] === null && $asText !== null && preg_match('/^AS(\d+)/i', $asText, $m) === 1) {
                $payload['asn'] = (int) $m[1];
            }
            if ($payload['asn_org'] === null) {
                $payload['asn_org'] = self::str($apiGeo['asname'] ?? null) ?: $asText;
            }
            if ($payload['org'] === null) {
                $payload['org'] = self::str($apiGeo['org'] ?? null) ?: self::str($apiGeo['isp'] ?? null);
            }
        }

        if ($payload['asn'] === null) {
            $info = $this->viaBreaker(RipestatSource::NAME, $degraded, fn (): ?array => $this->ripestat->networkInfo($ip));
            if ($info !== null) {
                $payload['source'][] = RipestatSource::NAME;
                if ($payload['asn'] === null && is_string($info['asn'] ?? null) && preg_match('/(\d+)/', $info['asn'], $m) === 1) {
                    $payload['asn'] = (int) $m[1];
                }
                if ($payload['asn_org'] === null) {
                    $payload['asn_org'] = self::str($info['holder'] ?? null);
                }
                if ($payload['org'] === null) {
                    $payload['org'] = self::str($info['holder'] ?? null);
                }
            }
        }

        $payload['type'] = AsnClassifier::classify(
            is_scalar($payload['org']) ? (string) $payload['org'] : null,
            is_scalar($payload['asn_org']) ? (string) $payload['asn_org'] : null,
        );
    }

    /**
     * @param  array<string, mixed>  $payload
     * @param  list<string>  $degraded
     */
    private function reverseDns(NetTarget $target, array &$payload, array &$degraded): void
    {
        $ip = $target->ips[0];
        $name = str_contains($ip, ':') ? self::reverseV6($ip) : implode('.', array_reverse(explode('.', $ip))).'.in-addr.arpa';

        $answer = null;
        foreach ($this->resolvers as $resolver) {
            $answer = $this->dns->query($resolver, $name, 'PTR', 2);
            if ($answer !== null) {
                break;
            }
            $degraded[] = 'dns:'.$resolver;
        }

        $ptr = $answer?->records['PTR'][0] ?? null;
        if (! is_string($ptr)) {
            return;
        }

        $payload['ptr'] = rtrim(mb_strtolower($ptr), '.');

        // Forward-confirmation (CRFC 1912 §2.1): does the PTR name point back?
        foreach ($this->resolvers as $resolver) {
            $forward = $this->dns->query($resolver, $payload['ptr'], 'A', 2);
            $addresses = $forward->records['A'] ?? [];
            if ($forward === null) {
                continue;
            }
            $payload['ptr_confirmed'] = in_array($ip, $addresses, true);

            return;
        }

        $payload['ptr_confirmed'] = false;
    }

    /** @param array<string, mixed> $payload */
    private function v6Reachability(NetTarget $target, array &$payload): void
    {
        $v6 = null;
        foreach ($target->ips as $ip) {
            if (str_contains($ip, ':')) {
                $v6 = $ip;

                break;
            }
        }

        if ($v6 === null) {
            return; // no AAAA on the target — nothing to say honestly
        }

        $probe = $this->v6Probe ?? static function (string $ip, int $timeoutSeconds): bool {
            $socket = @stream_socket_client('tcp://['.$ip.']:443', $errno, $errstr, $timeoutSeconds);
            if (is_resource($socket)) {
                fclose($socket);

                return true;
            }

            return false;
        };

        $payload['v6_reach'] = ($probe)($v6, 2) ? 'reachable' : 'no-route';
    }

    /**
     * Breaker-guarded source call: open breaker → skip with a degraded note;
     * failure records, success resets.
     *
     * @param  list<string>  $degraded
     * @template T
     *
     * @param  Closure(): T  $call
     * @return T|null
     */
    private function viaBreaker(string $source, array &$degraded, \Closure $call): mixed
    {
        if ($this->breaker !== null && ! $this->breaker->allow($source)) {
            $degraded[] = 'circuit:'.$source;

            return null;
        }

        $result = $call();

        if ($this->breaker !== null) {
            $result === null
                ? $this->breaker->recordFailure($source)
                : $this->breaker->recordSuccess($source);
        }

        if ($result === null) {
            $degraded[] = $source;
        }

        return $result;
    }

    private static function str(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    private static function reverseV6(string $ip): string
    {
        $packed = @inet_pton($ip);
        if ($packed === false || strlen($packed) !== 16) {
            return 'invalid.arpa';
        }

        return implode('.', array_reverse(str_split(bin2hex($packed)))).'.ip6.arpa';
    }
}
