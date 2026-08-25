<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\FetcherContract;
use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Sources\FetchOutcome;

/**
 * /sec security-headers audit (RFC §7.8): table-driven header checks, stack
 * fingerprint (self-declared only), RFC 9116 security.txt presence. CORS /
 * HTTP-methods probes run as extra single requests behind options flags.
 */
final class SecHeadersProbe implements NettoolsProbeContract
{
    public const string FLAG_CORS_CHECK = 'cors_check';

    public const string FLAG_METHODS_CHECK = 'methods_check';

    private const int BODY_SNIFF_BYTES = 65536;

    /** @var list<array{header:string, id:string, severity:'high'|'warn', hint:string}> */
    private const array HEADER_RULES = [
        ['Strict-Transport-Security', 'no_hsts', 'warn', 'add Strict-Transport-Security: max-age=31536000; includeSubDomains'],
        ['Content-Security-Policy', 'no_csp', 'warn', 'start with a report-only CSP, then enforce'],
        ['X-Frame-Options', 'no_xfo', 'warn', 'set X-Frame-Options: DENY or frame-ancestors CSP'],
        ['X-Content-Type-Options', 'no_xcto', 'warn', 'set X-Content-Type-Options: nosniff'],
        ['Referrer-Policy', 'no_referrer_policy', 'warn', 'set Referrer-Policy: strict-origin-when-cross-origin'],
    ];

    public function __construct(private readonly FetcherContract $fetcher)
    {
    }

    public function name(): string
    {
        return 'sec';
    }

    public function ttlSeconds(): int
    {
        return 3600;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        $startedAt = microtime(true);
        $scheme = $options->flag(HttpProbe::FLAG_SCHEME_HTTP) ? 'http' : 'https';
        $url = $scheme.'://'.$target->host.'/';

        // Pin every request to the pipeline-resolved IP — no fresh DNS from
        // any of this probe's requests (single-resolution invariant §4.3,
        // todo P1-2: closes the DNS-rebinding TOCTOU window).
        $pinIp = HttpProbe::sameFamilyIp($target->ips, str_contains($target->host, ':'));
        $pin = self::pinFor($target->host, self::portOf($url), $ip = $pinIp);

        $outcome = $this->fetcher->fetch($url, 'GET', $options->timeoutSeconds, curlOptions: $pin);

        if ($outcome->isTransportFailure()) {
            return new ProbeResult(
                probe: $this->name(),
                fetchedAt: 0,
                latencyMs: (int) round((microtime(true) - $startedAt) * 1000),
                degradedSources: [],
                payload: [
                    'host' => $target->host,
                    'error' => $outcome->error ?? 'other',
                    'headers' => [],
                    'findings' => [],
                    'stack' => [],
                    'security_txt' => null,
                    'cors' => null,
                    'methods' => null,
                ],
            );
        }

        $headers = self::lowerHeaders($outcome);
        $sniff = mb_substr($outcome->body, 0, self::BODY_SNIFF_BYTES);

        $findings = [];
        foreach (self::HEADER_RULES as [$header, $id, $severity, $hint]) {
            if (! isset($headers[strtolower($header)])) {
                $findings[] = ['severity' => $severity, 'id' => $id, 'detail' => "missing {$header} — {$hint}"];
            }
        }
        if (($hsts = $headers['strict-transport-security'] ?? null) !== null && ! preg_match('/max-age=(\d+)/i', (string) $hsts, $m)) {
            $findings[] = ['severity' => 'warn', 'id' => 'hsts_no_max_age', 'detail' => 'HSTS without max-age'];
        } elseif (isset($m[1]) && (int) $m[1] < 15552000) {
            $findings[] = ['severity' => 'info', 'id' => 'hsts_low_max_age', 'detail' => 'HSTS max-age below 180d'];
        }
        if (isset($headers['server']) && preg_match('/\d+\.\d+/', (string) $headers['server'])) {
            $findings[] = ['severity' => 'info', 'id' => 'version_banner', 'detail' => 'Server header declares a version — suppress it'];
        }

        $securityTxt = $this->securityTxt($target, $options, $pinIp);
        if (is_array($securityTxt) && ($securityTxt['present'] ?? false) === false) {
            $findings[] = ['severity' => 'info', 'id' => 'security_txt_missing', 'detail' => 'no /.well-known/security.txt — publish an RFC 9116 contact'];
        }

        $cors = $options->flag(self::FLAG_CORS_CHECK) ? $this->corsCheck($url, $options, $pinIp) : null;
        if (is_array($cors) && ($cors['verdict'] ?? '') === 'high') {
            $findings[] = ['severity' => 'high', 'id' => str_contains((string) $cors['detail'], 'wildcard') ? 'cors_wildcard_credentials' : 'cors_origin_reflection', 'detail' => (string) $cors['detail']];
        }

        $methods = $options->flag(self::FLAG_METHODS_CHECK) ? $this->methodsCheck($url, $options, $pinIp) : null;
        if (is_array($methods) && ($methods['trace'] ?? false) === true) {
            $findings[] = ['severity' => 'warn', 'id' => 'trace_enabled', 'detail' => 'TRACE method enabled — disable legacy methods at the web server'];
        }

        $hstsInfo = self::parseHsts($headers);
        $preload = null;
        if ($hstsInfo['present'] && ($hstsInfo['preload'] ?? false)) {
            $preload = $this->preloadStatus($target->host, $options);
            if (is_array($preload) && ($preload['eligible'] ?? true) === false) {
                $findings[] = ['severity' => 'info', 'id' => 'hsts_not_preload_eligible', 'detail' => 'not preload-eligible per hstspreload.org — raise max-age / add includeSubDomains'];
            }
        }

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: (int) round((microtime(true) - $startedAt) * 1000),
            degradedSources: [],
            payload: [
                'host' => $target->host,
                'error' => null,
                'status' => $outcome->status,
                'headers' => $headers,
                'hsts' => $hstsInfo,
                'csp' => isset($headers['content-security-policy']),
                'findings' => $findings,
                'stack' => self::fingerprint($headers, $sniff),
                'security_txt' => $securityTxt,
                'cors' => $cors,
                'methods' => $methods,
                'preload' => $preload,
            ],
        );
    }

    /**
     * hstspreload.org eligibility (RFC §7.8 advanced action). Offline /
     * source-down → null (no finding — never a fake pass).
     *
     * @return array{eligible:bool, status:?string}|null
     */
    private function preloadStatus(string $host, ProbeOptions $options): ?array
    {
        $outcome = $this->fetcher->fetch(
            'https://hstspreload.org/?domain='.rawurlencode($host),
            'GET',
            min($options->timeoutSeconds, 3),
            ['Accept' => 'application/json'],
        );

        $body = json_decode($outcome->body, true);
        if ($outcome->status !== 200 || ! is_array($body)) {
            return null;
        }

        return [
            'eligible' => (($body['status'] ?? '') === 'ok') && (($body['errors'] ?? []) === []),
            'status' => is_string($body['status'] ?? null) ? $body['status'] : null,
        ];
    }

    /** @return array<int, mixed> CURLOPT_RESOLVE pin when an approved IP exists */
    private static function pinFor(string $host, int $port, ?string $ip): array
    {
        return $ip !== null ? [CURLOPT_RESOLVE => ["{$host}:{$port}:{$ip}"]] : [];
    }

    private static function portOf(string $url): int
    {
        return (int) (parse_url($url, PHP_URL_PORT) ?: (strtolower((string) parse_url($url, PHP_URL_SCHEME)) === 'http' ? 80 : 443));
    }

    /**
     * Heuristic stack fingerprint from self-declared markers only.
     *
     * @param  array<string, string>  $headers
     * @return list<array{kind: string, name: string}>
     */
    private static function fingerprint(array $headers, string $bodySniff): array
    {
        $stack = [];
        $mark = static function (string $kind, string $name) use (&$stack): void {
            foreach ($stack as $entry) {
                if ($entry['name'] === $name) {
                    return;
                }
            }
            $stack[] = ['kind' => $kind, 'name' => $name];
        };

        if (isset($headers['cf-ray'])) {
            $mark('CDN/proxy', 'Cloudflare');
        }
        if (isset($headers['x-varnish']) || strtolower((string) ($headers['via'] ?? '')) !== '') {
            $mark('CDN/proxy', 'Varnish/Via proxy');
        }
        if (str_contains($bodySniff, 'wp-content')) {
            $mark('CMS', 'WordPress');
        }
        if (str_contains($bodySniff, '/sites/default/')) {
            $mark('CMS', 'Drupal');
        }
        if (str_contains($bodySniff, 'Joomla')) {
            $mark('CMS', 'Joomla');
        }
        if (str_contains($bodySniff, 'XSRF-TOKEN') || str_contains($bodySniff, 'laravel_session')) {
            $mark('Framework', 'Laravel');
        }
        if (str_contains($bodySniff, '__NEXT_DATA__') || str_contains($bodySniff, '/_next/')) {
            $mark('Framework', 'Next.js');
        }
        if (str_contains($bodySniff, '__NUXT__')) {
            $mark('Framework', 'Nuxt');
        }
        if (is_string($headers['x-powered-by'] ?? null)) {
            if (stripos((string) $headers['x-powered-by'], 'php') !== false) {
                $mark('Language runtime', 'PHP');
            }
            if (stripos((string) $headers['x-powered-by'], 'express') !== false) {
                $mark('Framework', 'Express');
            }
            if (stripos((string) $headers['x-powered-by'], 'asp.net') !== false) {
                $mark('Framework', 'ASP.NET');
            }
        }

        return $stack;
    }

    /** @param  array<string, string>  $headers */
    private static function parseHsts(array $headers): array
    {
        $raw = $headers['strict-transport-security'] ?? null;
        if ($raw === null) {
            return ['present' => false];
        }

        preg_match('/max-age=(\d+)/i', $raw, $m);

        return [
            'present' => true,
            'max_age' => isset($m[1]) ? (int) $m[1] : null,
            'include_subdomains' => stripos($raw, 'includeSubDomains') !== false,
            'preload' => stripos($raw, 'preload') !== false,
        ];
    }

    /** @param  array<string, string>  $outcomeHeaders */
    private static function lowerHeaders(FetchOutcome $outcome): array
    {
        $out = [];
        foreach ($outcome->headers as $name => $value) {
            $out[strtolower(trim((string) $name))] = trim((string) $value);
        }

        // merge repeated headers into one line for audit purposes
        return $out;
    }

    /** RFC 9116 /.well-known/security.txt presence + Contact parse. */
    private function securityTxt(NetTarget $target, ProbeOptions $options, ?string $pinIp): ?array
    {
        $outcome = $this->fetcher->fetch(
            'https://'.$target->host.'/.well-known/security.txt',
            'GET',
            min($options->timeoutSeconds, 3),
            curlOptions: self::pinFor($target->host, 443, $pinIp),
        );
        if ($outcome->status !== 200 || ! str_contains(strtolower((string) $outcome->header('Content-Type')), 'text/plain')) {
            return ['present' => false];
        }

        preg_match('/^Contact:\s*(.+)$/mi', $outcome->body, $m);

        return [
            'present' => true,
            'contact' => $m[1] ?? null,
        ];
    }

    /** One preflight-style request; wildcard ACAO + credentials or origin reflection → high finding. */
    private function corsCheck(string $url, ProbeOptions $options, ?string $pinIp): array
    {
        $evilOrigin = 'https://nettools-corsscan.example';
        $outcome = $this->fetcher->fetch(
            $url,
            'OPTIONS',
            min($options->timeoutSeconds, 4),
            ['Origin' => $evilOrigin, 'Access-Control-Request-Method' => 'GET'],
            self::pinFor((string) parse_url($url, PHP_URL_HOST), self::portOf($url), $pinIp),
        );

        $acao = $outcome->header('Access-Control-Allow-Origin');
        $acac = $outcome->header('Access-Control-Allow-Credentials');

        if ($acao !== null && $acac !== null && str_contains(strtolower($acac), 'true')) {
            if (trim($acao) === '*') {
                return ['checked' => true, 'verdict' => 'high', 'detail' => 'ACAO:* combined with credentials=true — any site can read responses'];
            }

            if (trim($acao) === $evilOrigin) {
                return ['checked' => true, 'verdict' => 'high', 'detail' => 'arbitrary Origin reflected with credentials=true'];
            }
        }

        return ['checked' => true, 'verdict' => $acao !== null ? 'ok' : 'none', 'detail' => $acao ?? 'no ACAO on preflight'];
    }

    private function methodsCheck(string $url, ProbeOptions $options, ?string $pinIp): array
    {
        $pin = self::pinFor((string) parse_url($url, PHP_URL_HOST), self::portOf($url), $pinIp);
        $outcome = $this->fetcher->fetch($url, 'OPTIONS', min($options->timeoutSeconds, 4), curlOptions: $pin);
        $allow = strtoupper((string) ($outcome->header('Allow') ?? $outcome->header('Access-Control-Allow-Methods') ?? ''));

        $trace = in_array('TRACE', array_map('trim', explode(',', $allow)), true)
            || $this->fetcher->fetch($url, 'TRACE', min($options->timeoutSeconds, 3), curlOptions: $pin)->status < 500
                && $this->fetcher->fetch($url, 'TRACE', min($options->timeoutSeconds, 3), curlOptions: $pin)->status > 0;

        return ['checked' => true, 'trace' => $trace, 'allow' => $allow !== '' ? $allow : null];
    }
}
