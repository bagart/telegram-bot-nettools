<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

/**
 * stream-based DNS transport (blocking, bounded by the caller's timeout).
 * The server argument is a resolver IP from config — never raw user bytes.
 */
final class UdpDnsTransport implements DnsTransportContract
{
    private const int MAX_UDP_RESPONSE_BYTES = 65535;

    public function askUdp(string $serverIp, string $wireQuery, int $timeoutSeconds): ?string
    {
        $socket = $this->connect($this->endpoint($serverIp, 'udp'), $timeoutSeconds);
        if ($socket === false) {
            return null;
        }

        try {
            if (@fwrite($socket, $wireQuery) === false) {
                return null;
            }

            $response = @fread($socket, self::MAX_UDP_RESPONSE_BYTES);

            return is_string($response) && $response !== '' ? $response : null;
        } finally {
            fclose($socket);
        }
    }

    public function askTcp(string $serverIp, string $wireQuery, int $timeoutSeconds): ?string
    {
        $socket = $this->connect($this->endpoint($serverIp, 'tcp'), $timeoutSeconds);
        if ($socket === false) {
            return null;
        }

        try {
            $framed = pack('n', strlen($wireQuery)).$wireQuery;
            if (@fwrite($socket, $framed) === false) {
                return null;
            }

            $prefix = @fread($socket, 2);
            if (! is_string($prefix) || strlen($prefix) !== 2) {
                return null;
            }

            $expected = unpack('n', $prefix)[1];
            if ($expected === 0 || $expected > self::MAX_UDP_RESPONSE_BYTES) {
                return null;
            }

            $buffer = '';
            while (strlen($buffer) < $expected) {
                $chunk = @fread($socket, $expected - strlen($buffer));
                if (! is_string($chunk) || $chunk === '') {
                    break;
                }
                $buffer .= $chunk;
            }

            return strlen($buffer) === $expected ? $buffer : null;
        } finally {
            fclose($socket);
        }
    }

    private function endpoint(string $serverIp, string $scheme): string
    {
        return str_contains($serverIp, ':')
            ? "{$scheme}://{$serverIp}"
            : "{$scheme}://{$serverIp}:53";
    }

    private function connect(string $target, int $timeoutSeconds): mixed
    {
        $errno = 0;
        $error = '';

        $socket = @stream_socket_client($target, $errno, $error, (float) $timeoutSeconds);

        if ($socket !== false) {
            stream_set_timeout($socket, $timeoutSeconds);
        }

        return $socket;
    }
}
