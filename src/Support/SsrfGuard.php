<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBotNettools\Results\GuardVerdict;

/**
 * SSRF guard matrix (RFC §5.2). Pure — classification only, no DNS.
 * Documentation ranges (TEST-NET) are allowed but labeled.
 */
final class SsrfGuard
{
    /** @var array<string, string> CIDR => reason */
    private const array BLOCKED_V4 = [
        '127.0.0.0/8' => 'loopback',
        '10.0.0.0/8' => 'private (RFC1918)',
        '172.16.0.0/12' => 'private (RFC1918)',
        '192.168.0.0/16' => 'private (RFC1918)',
        '169.254.0.0/16' => 'link-local / cloud metadata',
        '100.64.0.0/10' => 'CGNAT',
        '224.0.0.0/4' => 'multicast',
        '240.0.0.0/4' => 'reserved',
        '255.255.255.255/32' => 'broadcast',
        '0.0.0.0/8' => 'unspecified/reserved',
    ];

    /** @var array<string, string> CIDR => label */
    private const array LABELED_V4 = [
        '192.0.2.0/24' => 'TEST-NET-1',
        '198.51.100.0/24' => 'TEST-NET-2',
        '203.0.113.0/24' => 'TEST-NET-3',
    ];

    /** @var array<string, string> */
    private const array BLOCKED_V6 = [
        '::1/128' => 'loopback',
        'fc00::/7' => 'unique local (ULA)',
        'fe80::/10' => 'link-local',
        'ff00::/8' => 'multicast',
        '::/128' => 'unspecified',
    ];

    private const array LABELED_V6 = [
        '2001:db8::/32' => 'TEST-NET-2 (doc)',
    ];

    /**
     * Classify a single address against the matrix.
     * Blocked → blocked verdict; documentation ranges → labeled allow;
     * global unicast → plain allow.
     */
    public function classify(string $ip): GuardVerdict
    {
        if (! str_contains($ip, ':')) {
            foreach (self::BLOCKED_V4 as $cidr => $reason) {
                if ($this->inCidr($ip, $cidr)) {
                    return GuardVerdict::block($reason);
                }
            }
            foreach (self::LABELED_V4 as $cidr => $label) {
                if ($this->inCidr($ip, $cidr)) {
                    return GuardVerdict::allow($label);
                }
            }

            return GuardVerdict::allow();
        }

        // IPv4-mapped IPv6 must be judged by its embedded v4 address
        $v4 = filter_var(substr($ip, 7), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        if ($v4 !== false && stripos($ip, '::ffff:') === 0) {
            return $this->classify($v4);
        }

        foreach (self::BLOCKED_V6 as $cidr => $reason) {
            if ($this->inCidr($ip, $cidr)) {
                return GuardVerdict::block($reason);
            }
        }
        foreach (self::LABELED_V6 as $cidr => $label) {
            if ($this->inCidr($ip, $cidr)) {
                return GuardVerdict::allow($label);
            }
        }

        return GuardVerdict::allow();
    }

    public function inCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr);

        $ipBytes = @inet_pton($ip);
        $netBytes = @inet_pton($subnet);
        if ($ipBytes === false || $netBytes === false || strlen($ipBytes) !== strlen($netBytes)) {
            return false;
        }

        $maxBits = strlen($ipBytes) * 8;
        $bits = min((int) $bits, $maxBits);

        $fullBytes = intdiv($bits, 8);
        $remainderBits = $bits % 8;

        if ($fullBytes > 0 && substr($ipBytes, 0, $fullBytes) !== substr($netBytes, 0, $fullBytes)) {
            return false;
        }

        if ($remainderBits === 0) {
            return true;
        }

        $mask = 0xFF << (8 - $remainderBits) & 0xFF;

        return ((ord($ipBytes[$fullBytes]) ^ ord($netBytes[$fullBytes])) & $mask) === 0;
    }
}
