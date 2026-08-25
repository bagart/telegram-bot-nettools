<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBotNettools\Contracts\Exceptions\InvalidTargetException;

/**
 * Target normalization pipeline (RFC §5.1):
 * trim → URL host extraction (port 80/443 only) → IDN→punycode →
 * structural checks → IP-literal detection. No DNS here.
 */
final class TargetNormalizer
{
    private const int MAX_HOST_LENGTH = 253;

    private const int MAX_LABEL_LENGTH = 63;

    /**
     * @throws InvalidTargetException
     */
    public function normalize(string $rawInput): ResolvedInput
    {
        $input = trim($rawInput);

        if ($input === '' || $input !== preg_replace('/[\x00-\x1f\x7f]/', '', $input)) {
            throw new InvalidTargetException($rawInput, 'empty input or control characters');
        }

        [$host, $port] = $this->splitUrl($rawInput, $input);
        $host = mb_strtolower($host);
        $host = rtrim($host, '.');

        if ($host === '') {
            throw new InvalidTargetException($rawInput, 'empty host');
        }

        if (str_contains($host, ':') || filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return new ResolvedInput($rawInput, $this->normalizeIpLiteral($rawInput, $host), true, $port);
        }

        return new ResolvedInput($rawInput, $this->normalizeHostname($rawInput, $host), false, $port);
    }

    /** @return array{string, ?int} */
    private function splitUrl(string $original, string $candidate): array
    {
        if (! str_contains($candidate, '://')) {
            return [$candidate, null];
        }

        $parts = parse_url($candidate);
        if ($parts === false || ! isset($parts['host']) || ! is_string($parts['host'])) {
            throw new InvalidTargetException($original, 'unparseable URL');
        }

        $port = isset($parts['port']) ? (int) $parts['port'] : null;
        if ($port !== null && ! in_array($port, [80, 443], true)) {
            throw new InvalidTargetException($original, "non-web port {$port} on URL input");
        }
        if (isset($parts['scheme']) && ! in_array(strtolower((string) $parts['scheme']), ['http', 'https'], true)) {
            throw new InvalidTargetException($original, 'unsupported URL scheme');
        }

        return [$parts['host'], $port];
    }

    private function normalizeIpLiteral(string $original, string $host): string
    {
        // Bracketed IPv6 ([::1]) from URL inputs
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            $host = substr($host, 1, -1);
        }

        // IPv4-mapped IPv6 (::ffff:10.0.0.1) collapses to its v4 form so the
        // SSRF matrix sees the real range — never a bypass tunnel.
        if (str_contains($host, ':')) {
            $mapped = filter_var(substr($host, 7), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
            if (stripos($host, '::ffff:') === 0 && $mapped !== false) {
                $host = $mapped;
            }
        }

        if (filter_var($host, FILTER_VALIDATE_IP) === false) {
            throw new InvalidTargetException($original, "invalid IP literal: {$host}");
        }

        return $host;
    }

    private function normalizeHostname(string $original, string $host): string
    {
        if (strlen($host) > self::MAX_HOST_LENGTH) {
            throw new InvalidTargetException($original, 'host exceeds 253 bytes');
        }

        if (preg_match('/[^a-z0-9.\-_]/i', $host) === 1) {
            $ascii = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($ascii === false || str_contains($ascii, ' ')) {
                throw new InvalidTargetException($original, "IDN conversion failed for {$host}");
            }
            $host = strtolower($ascii);

            if (strlen($host) > self::MAX_HOST_LENGTH) {
                throw new InvalidTargetException($original, 'punycode host exceeds 253 bytes');
            }
        }

        $labels = explode('.', $host);
        foreach ($labels as $label) {
            if ($label === '') {
                throw new InvalidTargetException($original, 'empty label');
            }
            if (strlen($label) > self::MAX_LABEL_LENGTH) {
                throw new InvalidTargetException($original, 'label exceeds 63 bytes');
            }
        }

        if (preg_match('/^[a-z0-9._-]+$/i', $host) !== 1) {
            throw new InvalidTargetException($original, "invalid hostname characters: {$host}");
        }

        return $host;
    }
}
