<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Support\SsrfGuard;
use PHPUnit\Framework\TestCase;

/**
 * SSRF guard matrix (RFC §5.2). Zero unguarded egress is success criterion 2.
 */
final class SsrfGuardTest extends TestCase
{
    private SsrfGuard $guard;

    protected function setUp(): void
    {
        $this->guard = new SsrfGuard();
    }

    public function test_blocked_matrix(): void
    {
        $blocked = [
            '127.0.0.1' => 'loopback',
            '127.8.8.8' => 'loopback',
            '10.1.2.3' => 'private (RFC1918)',
            '172.16.0.1' => 'private (RFC1918)',
            '172.31.255.254' => 'private (RFC1918)',
            '192.168.1.1' => 'private (RFC1918)',
            '169.254.169.254' => 'link-local / cloud metadata',
            '100.64.0.1' => 'CGNAT',
            '100.127.255.255' => 'CGNAT',
            '224.0.0.1' => 'multicast',
            '239.1.1.1' => 'multicast',
            '240.0.0.1' => 'reserved',
            '0.0.0.0' => 'unspecified/reserved',
            '::1' => 'loopback',
            'fc00::1' => 'unique local (ULA)',
            'fd12:3456::1' => 'unique local (ULA)',
            'fe80::1' => 'link-local',
            'ff02::1' => 'multicast',
            '::' => 'unspecified',
        ];

        foreach ($blocked as $ip => $reason) {
            $verdict = $this->guard->classify($ip);
            self::assertTrue($verdict->isBlocked(), "expected {$ip} blocked");
            self::assertSame($reason, $verdict->reason, "wrong reason for {$ip}");
        }
    }

    public function test_public_ranges_allowed(): void
    {
        foreach (['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700::1111'] as $ip) {
            self::assertTrue($this->guard->classify($ip)->allowed, "expected {$ip} allowed");
        }
    }

    public function test_boundary_addresses_outside_private_ranges(): void
    {
        foreach (['172.15.255.255', '172.32.0.0', '100.63.255.255', '100.128.0.0', '11.0.0.1'] as $ip) {
            self::assertTrue($this->guard->classify($ip)->allowed, "expected {$ip} allowed");
        }
    }

    public function test_documentation_ranges_allowed_but_labeled(): void
    {
        $labeled = [
            '192.0.2.1' => 'TEST-NET-1',
            '198.51.100.7' => 'TEST-NET-2',
            '203.0.113.9' => 'TEST-NET-3',
            '2001:db8::1' => 'TEST-NET-2 (doc)',
        ];

        foreach ($labeled as $ip => $label) {
            $verdict = $this->guard->classify($ip);
            self::assertTrue($verdict->allowed, "expected {$ip} allowed");
            self::assertSame($label, $verdict->label);
        }
    }

    public function test_ipv4_mapped_ipv6_is_judged_as_ipv4(): void
    {
        self::assertTrue($this->guard->classify('::ffff:10.0.0.1')->isBlocked());
        self::assertTrue($this->guard->classify('::ffff:169.254.169.254')->isBlocked());
        self::assertTrue($this->guard->classify('::ffff:8.8.8.8')->allowed);
    }

    public function test_in_cidr_boundaries(): void
    {
        self::assertTrue($this->guard->inCidr('172.16.0.0', '172.16.0.0/12'));
        self::assertTrue($this->guard->inCidr('172.31.255.255', '172.16.0.0/12'));
        self::assertFalse($this->guard->inCidr('172.32.0.0', '172.16.0.0/12'));
        self::assertFalse($this->guard->inCidr('8.8.8.8', '10.0.0.0/8'));
    }

    public function test_in_cidr_bit_boundary(): void
    {
        self::assertTrue($this->guard->inCidr('100.64.0.0', '100.64.0.0/10'));
        self::assertTrue($this->guard->inCidr('100.127.0.0', '100.64.0.0/10'));
        self::assertFalse($this->guard->inCidr('100.128.0.0', '100.64.0.0/10'));
    }
}
