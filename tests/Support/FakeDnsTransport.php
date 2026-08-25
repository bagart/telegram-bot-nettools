<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Support;

use BAGArt\TelegramBotNettools\Sources\DnsTransportContract;

/**
 * Builds realistic DNS response messages for fixture tests, including name
 * compression pointers, and serves them from a sequential queue: each query
 * consumes the next scripted entry (udp answer / tcp retry pair).
 */
final class FakeDnsTransport implements DnsTransportContract
{
    /** @var list<string> */
    public array $udpQueries = [];

    /** @var list<string> */
    public array $tcpQueries = [];

    private int $cursor = 0;

    /** @var list<array{udp?: string|null, tcp?: string|null}> */
    private array $scripted = [];

    /**
     * @param  array{udp?: string|null, tcp?: string|null}  $answer
     */
    public function script(array $answer): self
    {
        $this->scripted[] = $answer;

        return $this;
    }

    public function askUdp(string $serverIp, string $wireQuery, int $timeoutSeconds): ?string
    {
        $this->udpQueries[] = $wireQuery;

        return self::echoId($this->scripted[$this->cursor++]['udp'] ?? null, $wireQuery);
    }

    public function askTcp(string $serverIp, string $wireQuery, int $timeoutSeconds): ?string
    {
        $this->tcpQueries[] = $wireQuery;

        // the TCP retry belongs to the query that just consumed its entry
        return self::echoId($this->scripted[max(0, $this->cursor - 1)]['tcp'] ?? null, $wireQuery);
    }

    /** Real resolvers echo the query ID — patch it into the scripted body. */
    private static function echoId(?string $response, string $wireQuery): ?string
    {
        if ($response === null || strlen($response) < 2 || strlen($wireQuery) < 2) {
            return $response;
        }

        return substr($wireQuery, 0, 2).substr($response, 2);
    }

    /**
     * Header + question + answer records; names in answers reference the
     * question name via a compression pointer (offset 12) like real servers.
     *
     * @param  list<array{type: int, ttl?: int, rdata: string}>  $records
     */
    public static function response(string $questionName, int $qtype, array $records, int $flags = 0x8180): string
    {
        $question = self::name($questionName).pack('nn', $qtype, 1);

        $answers = '';
        foreach ($records as $record) {
            // pointer to offset 12 (the question QNAME)
            $answers .= "\xc0\x0c"
                .pack('nnNn', $record['type'], 1, $record['ttl'] ?? 300, strlen($record['rdata']))
                .$record['rdata'];
        }

        return pack('nnnnnn', random_int(0, 0xFFFF), $flags, 1, count($records), 0, 0)
            .$question
            .$answers;
    }

    public static function name(string $plain): string
    {
        if ($plain === '') {
            return "\x00";
        }

        $wire = '';
        foreach (explode('.', strtolower(rtrim($plain, '.'))) as $label) {
            $wire .= chr(strlen($label)).$label;
        }

        return $wire."\x00";
    }
}
