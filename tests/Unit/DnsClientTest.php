<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Contracts\Exceptions\InvalidTargetException;
use BAGArt\TelegramBotNettools\Sources\DnsAnswer;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Tests\Support\FakeDnsTransport;
use PHPUnit\Framework\TestCase;

/**
 * DnsClient wire-format contract (RFC §12): golden query bytes, decode
 * fixtures with compression pointers, TC→TCP retry, rcode mapping.
 */
final class DnsClientTest extends TestCase
{
    public function test_query_bytes_match_golden_wire_format_with_edns(): void
    {
        $wire = DnsClient::encodeQuery('example.com', 1, 0x1234);

        $header = '1234'          // id
            .'0100'               // RD=1
            .'0001'               // qdcount
            .'00000000'           // an/ns counts
            .'0001';              // arcount = 1 (EDNS OPT)
        $question = '076578616d706c6503636f6d00' // example.com
            .'0001'                              // QTYPE=A
            .'0001';                             // QCLASS=IN
        $opt = '00'              // root name
            .'0029'              // TYPE=OPT
            .sprintf('%04x', DnsClient::EDNS_BUFFER_SIZE) // requestor's UDP size
            .'00000000'          // extended rcode/flags
            .'0000';             // rdlength

        self::assertSame($header.$question.$opt, bin2hex($wire));
    }

    public function test_answer_id_mismatch_is_dropped_and_retried_bounded(): void
    {
        $transport = new class () implements \BAGArt\TelegramBotNettools\Sources\DnsTransportContract {
            public int $asked = 0;

            /** Spoofed answer: fixed WRONG id. */
            public function askUdp(string $serverIp, string $wireQuery, int $timeoutSeconds): ?string
            {
                $this->asked++;

                $body = FakeDnsTransport::response('example.com', 1, [
                    ['type' => 1, 'rdata' => inet_pton('93.184.216.34')],
                ]);

                return "\xbe\xef".substr($body, 2);
            }

            public function askTcp(string $serverIp, string $wireQuery, int $timeoutSeconds): ?string
            {
                return null;
            }
        };

        $answer = (new DnsClient($transport))->query('192.0.2.53', 'example.com', 'A', 2);

        self::assertNull($answer, 'off-path/spoofed answers must never be accepted');
        self::assertSame(2, $transport->asked, 'bounded fresh-ID retry');
    }

    public function test_matching_id_is_accepted_and_edns_opt_skipped_in_decode(): void
    {
        $query = DnsClient::encodeQuery('example.com', 1, 0x1234);
        $response = FakeDnsTransport::response('example.com', 1, [
            ['type' => 1, 'rdata' => inet_pton('93.184.216.34')],
        ]);

        $matched = DnsClient::decodeResponse(substr($query, 0, 2).substr($response, 2), 0x1234);
        $mismatched = DnsClient::decodeResponse($response, 0x4321);

        self::assertNotNull($matched);
        self::assertSame(['93.184.216.34'], $matched->records['A'], 'OPT record in additional section is skipped');
        self::assertNull($mismatched);
    }

    public function test_encode_rejects_bad_labels(): void
    {
        $this->expectException(InvalidTargetException::class);

        DnsClient::encodeQuery('example..'.'com', 1, 1);
    }

    public function test_decode_parses_a_record_with_compression_pointer(): void
    {
        $response = FakeDnsTransport::response('example.com', 1, [
            ['type' => 1, 'ttl' => 3600, 'rdata' => inet_pton('93.184.216.34')],
            ['type' => 28, 'ttl' => 300, 'rdata' => inet_pton('2606:2800:220:1:248:1893:25c8:1946')],
        ]);

        $answer = DnsClient::decodeResponse($response);

        self::assertNotNull($answer);
        self::assertSame(DnsAnswer::NOERROR, $answer->rcode);
        self::assertSame(['93.184.216.34'], $answer->records['A']);
        self::assertSame(['2606:2800:220:1:248:1893:25c8:1946'], $answer->records['AAAA']);
        self::assertSame(3600, $answer->ttls['A']);
    }

    public function test_decode_mx_txt_soa_caa(): void
    {
        $soaRdata = FakeDnsTransport::name('ns1.example.com')
            .FakeDnsTransport::name('hostmaster.example.com')
            .pack('N5', 2026010101, 7200, 900, 1209600, 300);
        $caaRdata = "\x00"."\x05".'issue'.'letsencrypt.org';
        $spfText = 'v=spf1 include:_spf.example.com ~all';
        $txtRdata = chr(strlen($spfText)).$spfText;

        $response = FakeDnsTransport::response('example.com', 6, [
            ['type' => 15, 'rdata' => pack('n', 10).FakeDnsTransport::name('mail.example.com')],
            ['type' => 16, 'rdata' => $txtRdata],
            ['type' => 6, 'rdata' => $soaRdata],
            ['type' => 257, 'rdata' => $caaRdata],
        ]);

        $answer = DnsClient::decodeResponse($response);

        self::assertNotNull($answer);
        self::assertSame(['10 mail.example.com'], $answer->records['MX']);
        self::assertSame(['v=spf1 include:_spf.example.com ~all'], $answer->records['TXT']);
        self::assertMatchesRegularExpression('/^ns1\.example\.com hostmaster\.example\.com serial=2026010101/', $answer->records['SOA'][0]);
        self::assertSame(['issue letsencrypt.org'], $answer->records['CAA']);
    }

    public function test_decode_dnskey_and_ds(): void
    {
        $dnskeyRdata = "\x01\x01"."\x03"."\x08".random_bytes(8);
        $dsRdata = "\x12\x34"."\x08"."\x02".hex2bin('aabbccdd');

        $response = FakeDnsTransport::response('example.com', 48, [
            ['type' => 48, 'rdata' => $dnskeyRdata],
            ['type' => 43, 'rdata' => $dsRdata],
        ]);

        $answer = DnsClient::decodeResponse($response);

        self::assertNotNull($answer);
        self::assertSame(['alg=8 flags=0x0101 key='.base64_encode(substr($dnskeyRdata, 4))], $answer->records['DNSKEY']);
        self::assertSame(['keytag=4660 alg=8 digesttype=2 digest=AABBCCDD'], $answer->records['DS']);
    }

    public function test_nxdomain_rcode_maps_to_status_name(): void
    {
        $response = FakeDnsTransport::response('missing.example', 1, [], flags: 0x8183);

        $answer = DnsClient::decodeResponse($response);

        self::assertNotNull($answer);
        self::assertSame(DnsAnswer::NXDOMAIN, $answer->rcode);
        self::assertSame('NXDOMAIN', $answer->statusName());
        self::assertSame([], $answer->records);
    }

    public function test_flags_are_exposed(): void
    {
        // AA bit (0x0400) + AD bit (0x0020) set
        $response = FakeDnsTransport::response('example.com', 1, [
            ['type' => 1, 'rdata' => inet_pton('93.184.216.34')],
        ], flags: 0x8420);

        $answer = DnsClient::decodeResponse($response);

        self::assertNotNull($answer);
        self::assertTrue($answer->authoritative);
        self::assertTrue($answer->dnssecAd);
        self::assertFalse($answer->truncated);
    }

    public function test_truncated_udp_answer_retries_over_tcp(): void
    {
        $transport = new FakeDnsTransport();
        $truncated = FakeDnsTransport::response('example.com', 1, [
            ['type' => 1, 'rdata' => inet_pton('93.184.216.34')],
        ], flags: 0x8380); // TC bit set

        $full = FakeDnsTransport::response('example.com', 1, [
            ['type' => 1, 'rdata' => inet_pton('93.184.216.34')],
            ['type' => 28, 'rdata' => inet_pton('2606:2800:220:1:248:1893:25c8:1946')],
        ]);
        // the fake transport stands in for the real one, which strips the
        // 2-byte length prefix before returning message bytes
        $transport->script(['udp' => $truncated, 'tcp' => $full]);

        $client = new DnsClient($transport);
        $answer = $client->query('1.1.1.1', 'example.com', 'A', 2);

        self::assertNotNull($answer);
        self::assertCount(1, $transport->udpQueries);
        self::assertCount(1, $transport->tcpQueries);
        self::assertSame($transport->udpQueries[0], $transport->tcpQueries[0], 'TCP retry must resend the identical wire query');
        self::assertFalse($answer->truncated, 'TCP answer replaces the truncated UDP one');
        self::assertSame(['93.184.216.34'], $answer->records['A']);
        self::assertCount(1, $answer->records['AAAA']);
    }

    public function test_transport_failure_yields_null(): void
    {
        $transport = new FakeDnsTransport();
        $transport->script([]);

        $client = new DnsClient($transport);

        self::assertNull($client->query('1.1.1.1', 'example.com', 'A', 2));
    }

    public function test_unknown_type_or_bad_resolver_is_refused_locally(): void
    {
        $transport = new FakeDnsTransport();
        $client = new DnsClient($transport);

        self::assertNull($client->query('not-an-ip', 'example.com', 'A', 2));
        self::assertNull($client->query('1.1.1.1', 'example.com', 'HINFO', 2));
        self::assertSame([], $transport->udpQueries, 'no network traffic for invalid input');
    }
}
