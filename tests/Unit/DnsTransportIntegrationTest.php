<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Sources\UdpDnsTransport;
use PHPUnit\Framework\TestCase;

/**
 * Hermetic integration test: real UdpDnsTransport sockets exercised against
 * a one-shot fixture server process (the RFC §12 "dnsmasq fixture" role) —
 * covers the actual UDP datagram path and the TCP length-prefix framing
 * without any external network.
 */
final class DnsTransportIntegrationTest extends TestCase
{
    private const string QUESTION = "\x07example\x03com\x00\x00\x01\x00\x01";

    public function test_udp_round_trip_against_local_fixture_server(): void
    {
        $answer = pack('nnnnnn', 0xABCD, 0x8180, 1, 1, 0, 0).self::QUESTION
            ."\xc0\x0c\x00\x01\x00\x01\x00\x00\x02\x58\x00\x04".inet_pton('93.184.216.34');

        $script = <<<'PHP'
            $sock = stream_socket_server('udp://127.0.0.1:0', $e, $es, STREAM_SERVER_BIND);
            fwrite(STDERR, 'bind='.var_export($sock !== false, true)." $e $es\n");
            if ($sock === false) {
                exit(1);
            }
            $address = (string) stream_socket_get_name($sock, false);
            fwrite(STDERR, 'PORT='.substr($address, strrpos($address, ':') + 1)."\n");
            fflush(STDERR);
            stream_set_blocking($sock, false);
            while (true) {
                $query = stream_socket_recvfrom($sock, 65535, 0, $from);
                if (is_string($query) && $query !== '') {
                    [$id] = array_values(unpack('n', substr($query, 0, 2)));
                    [$flags] = array_values(unpack('n', substr($query, 2, 2)));
                    $answer = substr_replace(hex2bin(getenv('MESSAGE_HEX')), pack('n', $id), 0, 2);
                    $answer = substr_replace($answer, pack('n', ($flags & 0x0100) | 0x8180), 2, 2);
                    stream_socket_sendto($sock, $answer, 0, $from);
                    exit(0);
                }
                usleep(10_000);
            }
            PHP;

        $port = $this->spawnFixture($script, ['MESSAGE_HEX' => bin2hex($answer)]);

        $result = (new UdpDnsTransport())->askUdp("127.0.0.1:{$port}", DnsClient::encodeQuery('example.com', 1, 0xABCD), 3);

        self::assertIsString($result);
        $decoded = DnsClient::decodeResponse($result);

        self::assertNotNull($decoded);
        self::assertSame(0, $decoded->rcode);
        self::assertSame(['93.184.216.34'], $decoded->records['A']);
    }

    public function test_tcp_framing_against_local_fixture_server(): void
    {
        $message = pack('nnnnnn', 0x4242, 0x8180, 1, 2, 0, 0).self::QUESTION
            ."\xc0\x0c\x00\x01\x00\x01\x00\x00\x02\x58\x00\x04".inet_pton('93.184.216.34')
            ."\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10".inet_pton('2606:2800:220:1:248:1893:25c8:1946');

        $script = <<<'PHP'
            $server = stream_socket_server('tcp://127.0.0.1:0', $e, $es);
            fwrite(STDERR, 'bind='.var_export($server !== false, true)." $e $es\n");
            if ($server === false) {
                exit(1);
            }
            $address = (string) stream_socket_get_name($server, false);
            fwrite(STDERR, 'PORT='.substr($address, strrpos($address, ':') + 1)."\n");
            fflush(STDERR);
            stream_set_blocking($server, false);
            while (true) {
                $conn = @stream_socket_accept($server, 0.5);
                if ($conn !== false) {
                    $prefix = fread($conn, 2);
                    if (strlen($prefix) === 2) {
                        $expected = unpack('n', $prefix)[1];
                        fread($conn, $expected);
                        $message = hex2bin(getenv('MESSAGE_HEX'));
                        fwrite($conn, pack('n', strlen($message)).$message);
                        fflush($conn);
                    }
                    fclose($conn);
                    exit(0);
                }
            }
            PHP;

        $port = $this->spawnFixture($script, ['MESSAGE_HEX' => bin2hex($message)]);

        $result = (new UdpDnsTransport())->askTcp("127.0.0.1:{$port}", DnsClient::encodeQuery('example.com', 1, 0x4242), 3);

        self::assertIsString($result);
        $decoded = DnsClient::decodeResponse($result);

        self::assertNotNull($decoded);
        self::assertSame(['93.184.216.34'], $decoded->records['A']);
        self::assertSame(['2606:2800:220:1:248:1893:25c8:1946'], $decoded->records['AAAA']);
    }

    /** @var resource|null */
    private $process = null;

    private ?string $fixtureLog = null;

    protected function tearDown(): void
    {
        if ($this->process !== null) {
            proc_terminate($this->process);
            proc_close($this->process);
            $this->process = null;
        }
    }

    /**
     * Spawns the fixture; it binds port 0 itself and announces its actual
     * port as "PORT=n" on stderr — the parent polls the log until ready.
     *
     * @param  array<string, string>  $env
     */
    private function spawnFixture(string $script, array $env): int
    {
        $file = sys_get_temp_dir().'/nettools-fixture-'.getmypid().'.php';
        file_put_contents($file, "<?php\n".$script);

        $this->fixtureLog = sys_get_temp_dir().'/nettools-fixture-'.getmypid().'.log';
        $logHandle = fopen($this->fixtureLog, 'wb');

        // array command form: no shell, no quoting layers
        $this->process = proc_open(
            [PHP_BINARY, '-d', 'error_reporting=E_ALL', $file],
            [1 => $logHandle, 2 => $logHandle],
            $pipes,
            null,
            $env,
        );
        self::assertIsResource($this->process, 'fixture proc_open failed');

        $deadline = microtime(true) + 10;
        $log = '';
        do {
            usleep(50_000);
            $log = (string) @file_get_contents($this->fixtureLog);
            if (preg_match('/^PORT=(\d+)$/m', $log, $m) === 1) {
                return (int) $m[1];
            }
        } while (microtime(true) < $deadline && proc_get_status($this->process)['running']);

        self::fail("fixture never announced its port; log:\n".$log);
    }

    protected function onNotSuccessfulTest(\Throwable $t): never
    {
        if ($this->fixtureLog !== null && is_file($this->fixtureLog)) {
            fwrite(STDERR, "\n--- fixture log ---\n".(string) file_get_contents($this->fixtureLog)."--- end ---\n");
        }

        throw $t;
    }
}
