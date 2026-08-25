<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;

/**
 * /ssl probe (RFC §7.7): one TLS handshake capturing the peer certificate
 * chain, negotiated protocol and ALPN, followed by a deterministic
 * certificate audit (validity, key strength, hostname semantics, chain,
 * offered protocol versions).
 *
 * The network access sits behind a Closure seam ({@see selfInspector()} is
 * the production implementation) so unit tests inject canned inspections.
 * "No TLS" is a distinct result carried in the payload — never an exception.
 *
 * @phpstan-type Inspection array{has_tls: bool, error?: ?string, protocol?: ?string, alpn?: list<string>, chain_count?: int, self_signed?: bool, ocsp_stapled?: bool, offered_protocols?: list<string>, cert?: ?array<string, mixed>}
 */
final class SslProbe implements NettoolsProbeContract
{
    public const int DEFAULT_PORT = 443;

    /** CA/Browser Forum ballot SC-081 maximum certificate lifetime. */
    public const int MAX_LIFETIME_DAYS = 398;

    /** @var list<string> lowercase fragments of disallowed signature algorithms */
    private const array WEAK_SIGNATURE_FRAGMENTS = ['sha1', 'md5'];

    /**
     * @param  \Closure(string, int, float, ?string=): ?Inspection  $tlsInspect
     *                    ($host, $port, $timeoutSeconds, $pinIp) returns the
     *                    normalized inspection or null when no TLS; $pinIp is
     *                    the pipeline-resolved address to connect to instead
     *                    of re-resolving $host (todo P1-2)
     */
    public function __construct(private readonly \Closure $tlsInspect)
    {
    }

    public function name(): string
    {
        return 'ssl';
    }

    public function ttlSeconds(): int
    {
        return 3600;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        $startedAt = microtime(true);

        $inspection = ($this->tlsInspect)(
            $target->host,
            self::DEFAULT_PORT,
            (float) max(1, min(10, $options->timeoutSeconds)),
            HttpProbe::sameFamilyIp($target->ips, str_contains($target->host, ':')),
        );

        $payload = self::payload($target->host, is_array($inspection) ? $inspection : null);
        ksort($payload);

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: (int) round((microtime(true) - $startedAt) * 1000),
            // Missing TLS is a legitimate answer, not a degradation.
            degradedSources: [],
            payload: $payload,
        );
    }

    /**
     * Production inspector: one unrestricted handshake (negotiated protocol,
     * ALPN, peer chain) plus restricted handshakes per protocol version to
     * learn what the endpoint still offers. Connects to $pinIp when given —
     * the caller's single resolution — keeping SNI/peer identity at $host.
     */
    public static function selfInspector(): \Closure
    {
        return static function (string $host, int $port, float $timeoutSeconds, ?string $pinIp = null): array {
            $primary = self::inspectHandshake($host, $port, $timeoutSeconds, null, $pinIp);

            if (! ($primary['has_tls'] ?? false)) {
                return $primary;
            }

            // Restricted version probes get a short per-attempt budget —
            // 4 serial handshakes must not multiply the wall time (todo P2-2).
            $probeTimeout = max(1.0, min(2.0, $timeoutSeconds));

            $offered = [];
            foreach (self::protocolAttempts() as $method => $label) {
                if ((self::inspectHandshake($host, $port, $probeTimeout, $method, $pinIp))['has_tls']) {
                    $offered[] = $label;
                }
            }

            return [...$primary, 'offered_protocols' => $offered];
        };
    }

    /**
     * Single TLS handshake. Verification is disabled on purpose: bad
     * certificates must be inspected, not rejected. $pinIp (when non-null) is
     * used as the connect address while SNI/peer_name stay at $host — no
     * fresh DNS inside the probe.
     *
     * @return array<string, mixed>
     */
    private static function inspectHandshake(string $host, int $port, float $timeoutSeconds, ?int $cryptoMethod, ?string $pinIp = null): array
    {
        $context = stream_context_create(['ssl' => array_filter([
            'capture_session_meta' => true,
            'peer_name' => $host,
            'SNI_enabled' => true,
            'alpn_protocols' => 'h2,http/1.1',
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true,
            'crypto_method' => $cryptoMethod,
        ])]);

        $connectHost = $pinIp ?? $host;
        $address = (str_contains($connectHost, ':') ? '['.$connectHost.']' : $connectHost).':'.$port;
        $stream = @stream_socket_client(
            'ssl://'.$address,
            $errno,
            $errstr,
            $timeoutSeconds,
            STREAM_CLIENT_CONNECT,
            $context,
        );

        if ($stream === false) {
            return ['has_tls' => false, 'error' => self::classifyConnectError($errno, $errstr)];
        }

        try {
            $ssl = (array) (stream_context_get_params($context)['ssl'] ?? []);
            $meta = (array) ($ssl['session_meta'] ?? []);
            $chain = self::dedupeChain($ssl);

            $leafParsed = $chain[0] !== null ? openssl_x509_parse($chain[0]) : false;
            if ($leafParsed === false) {
                return ['has_tls' => false, 'error' => 'tls'];
            }

            return [
                'has_tls' => true,
                'error' => null,
                'protocol' => self::normalizeProtocol(
                    isset($meta['protocol']) && is_string($meta['protocol']) ? $meta['protocol'] : null,
                ),
                'alpn' => isset($meta['alpn_selected_protocol']) && is_string($meta['alpn_selected_protocol'])
                    ? [$meta['alpn_selected_protocol']]
                    : [],
                'chain_count' => count($chain),
                'self_signed' => ($leafParsed['issuer'] ?? null) === ($leafParsed['subject'] ?? null),
                'cert' => self::parseLeaf($chain[0], $leafParsed),
            ];
        } finally {
            fclose($stream);
        }
    }

    /**
     * Leaf first, intermediates after; the raw chain may repeat the leaf.
     *
     * @return list<\OpenSSLCertificate>
     */
    private static function dedupeChain(array $ssl): array
    {
        $certificates = [];
        $seen = [];
        $raw = [
            $ssl['peer_certificate'] ?? null,
            ...(array) ($ssl['peer_certificate_chain'] ?? []),
        ];

        foreach ($raw as $certificate) {
            if (! $certificate instanceof \OpenSSLCertificate) {
                continue;
            }
            $fingerprint = openssl_x509_fingerprint($certificate, 'sha256');
            if ($fingerprint === false || isset($seen[$fingerprint])) {
                continue;
            }
            $seen[$fingerprint] = true;
            $certificates[] = $certificate;
        }

        return $certificates;
    }

    /** @return array<int|string, string> STREAM_CRYPTO_METHOD_* → label */
    private static function protocolAttempts(): array
    {
        return [
            STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT => 'TLS1.0',
            STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT => 'TLS1.1',
            STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT => 'TLS1.2',
            STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT => 'TLS1.3',
        ];
    }

    /** @return array<string, mixed> */
    private static function parseLeaf(\OpenSSLCertificate $certificate, array $parsed): array
    {
        $keyDetails = false;
        $publicKey = @openssl_pkey_get_public($certificate);
        if ($publicKey !== false) {
            $details = openssl_pkey_get_details($publicKey);
            if (is_array($details)) {
                $keyDetails = $details;
            }
        }

        $keyAlgorithms = [
            OPENSSL_KEYTYPE_RSA => 'RSA',
            OPENSSL_KEYTYPE_DSA => 'DSA',
            OPENSSL_KEYTYPE_EC => 'EC',
        ];

        $serial = null;
        foreach (['serialNumberHex', 'serialNumber'] as $serialField) {
            if (isset($parsed[$serialField]) && is_string($parsed[$serialField]) && $parsed[$serialField] !== '') {
                $serial = strtoupper($parsed[$serialField]);
                break;
            }
        }

        return [
            'subject_cn' => self::distinguishedValue((array) ($parsed['subject'] ?? []), 'CN'),
            'issuer_cn' => self::distinguishedValue((array) ($parsed['issuer'] ?? []), 'CN'),
            'issuer_org' => self::distinguishedValue((array) ($parsed['issuer'] ?? []), 'O'),
            'san' => self::sanNames((string) ($parsed['extensions']['subjectAltName'] ?? '')),
            'valid_from' => (int) ($parsed['validFrom_time_t'] ?? 0),
            'valid_to' => (int) ($parsed['validTo_time_t'] ?? 0),
            'sig_alg' => isset($parsed['signatureAlgorithmSN']) && is_string($parsed['signatureAlgorithmSN'])
                ? $parsed['signatureAlgorithmSN']
                : null,
            'key_alg' => $keyDetails !== false ? ($keyAlgorithms[(int) ($keyDetails['type'] ?? -1)] ?? null) : null,
            'key_bits' => isset($keyDetails['bits']) && is_int($keyDetails['bits']) ? $keyDetails['bits'] : null,
            'serial' => $serial,
            'sha256_fp' => openssl_x509_fingerprint($certificate, 'sha256') ?: null,
        ];
    }

    /**
     * Normalized payload; every key always present so cards can trust the shape.
     *
     * @return array<string, mixed>
     */
    private static function payload(string $host, ?array $inspection): array
    {
        $hasTls = (bool) ($inspection['has_tls'] ?? false);
        $now = time();

        $cert = null;
        if ($hasTls) {
            $rawCert = (array) ($inspection['cert'] ?? []);
            $validTo = (int) ($rawCert['valid_to'] ?? 0);
            $cert = [
                'subject_cn' => self::nullableString($rawCert['subject_cn'] ?? null),
                'issuer_cn' => self::nullableString($rawCert['issuer_cn'] ?? null),
                'issuer_org' => self::nullableString($rawCert['issuer_org'] ?? null),
                'san' => array_values(array_map(strval(...), array_filter(
                    (array) ($rawCert['san'] ?? []),
                    static fn (mixed $name): bool => is_scalar($name),
                ))),
                'valid_from' => (int) ($rawCert['valid_from'] ?? 0),
                'valid_to' => $validTo,
                'days_left' => (int) floor(($validTo - $now) / 86400),
                'sig_alg' => self::nullableString($rawCert['sig_alg'] ?? null),
                'key_alg' => self::nullableString($rawCert['key_alg'] ?? null),
                'key_bits' => isset($rawCert['key_bits']) && is_int($rawCert['key_bits']) ? $rawCert['key_bits'] : null,
                'serial' => self::nullableString($rawCert['serial'] ?? null),
                'sha256_fp' => self::nullableString($rawCert['sha256_fp'] ?? null),
            ];
        }

        $payload = [
            'host' => $host,
            'has_tls' => $hasTls,
            'error' => $hasTls ? null : self::nullableString($inspection['error'] ?? null) ?? 'other',
            'protocol' => self::normalizeProtocol(
                isset($inspection['protocol']) && is_string($inspection['protocol']) ? $inspection['protocol'] : null,
            ),
            'alpn' => array_values(array_map(strval(...), array_filter(
                (array) ($inspection['alpn'] ?? []),
                static fn (mixed $proto): bool => is_scalar($proto),
            ))),
            'cert' => $cert,
            'chain_count' => (int) ($inspection['chain_count'] ?? 0),
            'self_signed' => (bool) ($inspection['self_signed'] ?? false),
            'ocsp_stapled' => (bool) ($inspection['ocsp_stapled'] ?? false),
            'revocation' => 'unchecked',
            'offered_protocols' => array_values(array_map(strval(...), array_filter(
                (array) ($inspection['offered_protocols'] ?? []),
                static fn (mixed $proto): bool => is_scalar($proto),
            ))),
            'findings' => [],
        ];

        if ($hasTls) {
            // Honest coverage note (§7.7 revocation group): OCSP/CRL soft-fail
            // needs responder plumbing this deployment does not ship yet.
            $payload['findings'][] = [
                'severity' => 'info',
                'id' => 'revocation_unchecked',
                'detail' => 'revocation not checked in this deployment (no OCSP responder query)',
            ];

            if (! in_array('h2', $payload['alpn'], true)) {
                $payload['findings'][] = [
                    'severity' => 'info',
                    'id' => 'no_h2',
                    'detail' => 'HTTP/2 not negotiated — enable ALPN h2',
                ];
            }
        }

        if ($hasTls && $payload['cert'] !== null) {
            $payload['findings'] = [...$payload['findings'], ...self::auditFindings($now, $payload)];
        }

        return $payload;
    }

    /**
     * Deterministic rules (RFC §7.7), stable order: validity → key → identity
     * → chain → protocols.
     *
     * @param  array<string, mixed>  $payload
     * @return list<array{severity: 'high'|'warn'|'info', id: string, detail: string}>
     */
    private static function auditFindings(int $now, array $payload): array
    {
        $findings = [];
        $cert = (array) ($payload['cert'] ?? []);

        $daysLeft = (int) $cert['days_left'];
        $add = static function (string $severity, string $id, string $detail) use (&$findings): void {
            $findings[] = ['severity' => $severity, 'id' => $id, 'detail' => $detail];
        };

        if ((int) $cert['valid_to'] < $now) {
            $expiredOn = gmdate('Y-m-d', (int) $cert['valid_to']);
            $add('high', 'expired', 'certificate expired '.$expiredOn.' ('.abs($daysLeft).' day(s) ago)');
        } elseif ((int) $cert['valid_from'] > $now) {
            $add('high', 'not_valid_yet', 'certificate is not valid before '.gmdate('Y-m-d', (int) $cert['valid_from']));
        } elseif ($daysLeft < 14) {
            $add('high', 'expiring_soon', 'expires in '.$daysLeft.' day(s) — renew immediately');
        } elseif ($daysLeft < 30) {
            $add('warn', 'expiring', 'expires in '.$daysLeft.' day(s)');
        }

        if ((int) $cert['valid_to'] - (int) $cert['valid_from'] > self::MAX_LIFETIME_DAYS * 86400) {
            $add('info', 'long_lifetime', 'certificate lifetime exceeds 398 days (CA/B forum limit)');
        }

        $sigAlg = strtolower((string) ($cert['sig_alg'] ?? ''));
        if ($sigAlg !== '' && array_any(self::WEAK_SIGNATURE_FRAGMENTS, static fn (string $weak): bool => str_contains($sigAlg, $weak))) {
            $add('high', 'weak_sig', 'weak signature algorithm: '.$cert['sig_alg']);
        }

        $keyAlg = is_string($cert['key_alg']) ? $cert['key_alg'] : null;
        $keyBits = is_int($cert['key_bits']) ? $cert['key_bits'] : null;
        $weakKey = match (true) {
            $keyAlg === 'DSA' => true,
            $keyAlg === 'RSA' && ($keyBits ?? 0) < 2048 => true,
            $keyAlg === 'EC' && ($keyBits ?? 0) < 256 => true,
            default => false,
        };
        if ($weakKey) {
            $add('high', 'weak_key', 'weak key: '.$keyAlg.' '.$keyBits.' bits');
        }

        if ((bool) $payload['self_signed']) {
            $add('high', 'self_signed', 'certificate is self-signed');
        }

        $candidates = array_values(array_filter([
            is_string($cert['subject_cn']) ? $cert['subject_cn'] : null,
            ...(array) $cert['san'],
        ]));
        if (! self::hostnameMatches((string) $payload['host'], $candidates)) {
            $shown = $candidates === [] ? '(no CN/SAN names)' : implode(', ', array_slice($candidates, 0, 4));
            $add('high', 'hostname_mismatch', 'certificate does not cover '.$payload['host'].' — names: '.$shown);
        }

        if ((int) $payload['chain_count'] < 2) {
            $add('warn', 'incomplete_chain', 'only '.(int) $payload['chain_count'].' certificate(s) presented — chain may be incomplete');
        }

        $seen = array_values(array_unique(array_filter([
            is_string($payload['protocol']) ? $payload['protocol'] : null,
            ...(array) $payload['offered_protocols'],
        ])));
        $legacy = array_values(array_intersect($seen, ['TLS1.0', 'TLS1.1']));
        if ($legacy !== []) {
            $add('high', 'legacy_protocol', 'endpoint still offers legacy TLS: '.implode(', ', $legacy));
        }

        return $findings;
    }

    /**
     * Wildcard semantics (RFC §7.7): "*.example.com" matches exactly one
     * leading label — never a deeper label stack, never the apex domain.
     *
     * @param  list<string>  $candidates
     */
    public static function hostnameMatches(string $host, array $candidates): bool
    {
        $host = rtrim(mb_strtolower(trim($host)), '.');

        foreach ($candidates as $candidate) {
            if (! is_string($candidate) || trim($candidate) === '') {
                continue;
            }
            $candidate = rtrim(mb_strtolower(trim($candidate)), '.');

            if (! str_contains($candidate, '*')) {
                if ($candidate === $host) {
                    return true;
                }

                continue;
            }

            if (! str_starts_with($candidate, '*.')) {
                continue;
            }

            $suffix = substr($candidate, 1);
            if (! str_ends_with($host, $suffix)) {
                continue;
            }

            $prefix = substr($host, 0, -strlen($suffix));
            if ($prefix !== '' && ! str_contains($prefix, '.')) {
                return true;
            }
        }

        return false;
    }

    private static function classifyConnectError(int $errno, string $errstr): string
    {
        $message = strtolower($errstr);

        return match (true) {
            $errno === 111 || str_contains($message, 'refused') => 'refused',
            $errno === 110 || str_contains($message, 'timed out') || str_contains($message, 'timeout') => 'timeout',
            str_contains($message, 'ssl')
                || str_contains($message, 'certificate')
                || str_contains($message, 'handshake')
                || str_contains($message, 'protocol') => 'tls',
            default => 'other',
        };
    }

    private static function normalizeProtocol(?string $protocol): ?string
    {
        $trimmed = trim((string) $protocol);

        return $trimmed === '' ? null : str_replace(['TLSv', 'SSLv'], ['TLS', 'SSL'], $trimmed);
    }

    /**
     * @param  array<string, mixed>  $distinguishedName
     */
    private static function distinguishedValue(array $distinguishedName, string $field): ?string
    {
        $value = $distinguishedName[$field] ?? null;
        if (is_array($value)) {
            $value = $value[0] ?? null;
        }

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    /** @return list<string> */
    private static function sanNames(string $subjectAltName): array
    {
        $names = [];
        foreach (explode(',', $subjectAltName) as $entry) {
            $entry = trim($entry);
            if (! str_starts_with(strtolower($entry), 'dns:')) {
                continue;
            }
            $name = trim(substr($entry, 4));
            if ($name !== '') {
                $names[] = $name;
            }
        }

        return array_values(array_unique($names));
    }

    private static function nullableString(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }
}
