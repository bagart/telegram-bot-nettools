<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

use BAGArt\TelegramBotNettools\Contracts\Exceptions\InvalidTargetException;

/**
 * Internal minimal DNS client (RFC D5): UDP with TCP retry on truncation.
 * Supports exactly the record set the module needs (§10.2) — owning the
 * client keeps zero new deps and precise per-query timeouts. Name
 * decompression handles pointers with a loop guard; malformed answers
 * degrade to null, never throw beyond InvalidTarget on bad input hosts.
 */
final class DnsClient
{
    public const array TYPES = [
        'A' => 1,
        'NS' => 2,
        'CNAME' => 5,
        'SOA' => 6,
        'PTR' => 12,
        'MX' => 15,
        'TXT' => 16,
        'AAAA' => 28,
        'DS' => 43,
        'DNSKEY' => 48,
        'CAA' => 257,
    ];

    private const int HEADER_BYTES = 12;

    private const int MAX_POINTER_JUMPS = 32;

    private const int MAX_NAME_BYTES = 255;

    public function __construct(private readonly DnsTransportContract $transport)
    {
    }

    /**
     * @param  'A'|'NS'|'CNAME'|'SOA'|'PTR'|'MX'|'TXT'|'AAAA'|'DS'|'DNSKEY'|'CAA'  $recordType
     */
    public function query(string $resolverIp, string $host, string $recordType, int $timeoutSeconds): ?DnsAnswer
    {
        $qtype = self::TYPES[strtoupper($recordType)] ?? null;
        if ($qtype === null || ! preg_match('/^(?:\d{1,3}(?:\.\d{1,3}){3})$/', $resolverIp)) {
            return null;
        }

        try {
            $query = self::encodeQuery($host, $qtype);
        } catch (InvalidTargetException) {
            return null;
        }

        $response = $this->transport->askUdp($resolverIp, $query, $timeoutSeconds);
        if ($response === null) {
            return null;
        }

        $answer = self::decodeResponse($response);
        if ($answer !== null && $answer->truncated) {
            // Truncated UDP answer — RFC 1035 §4.2.1 requires TCP retry
            $tcpResponse = $this->transport->askTcp($resolverIp, $query, $timeoutSeconds);
            $answer = $tcpResponse === null ? $answer : self::decodeResponse($tcpResponse);
        }

        return $answer;
    }

    /**
     * Wire query bytes: header (RD=1) + one question entry.
     *
     * @throws InvalidTargetException empty/oversized labels or host
     */
    public static function encodeQuery(string $host, int $qtype, ?int $id = null): string
    {
        $wire = '';
        foreach (explode('.', strtolower(rtrim($host, '.'))) as $label) {
            $length = strlen($label);
            if ($label === '' || $length > 63) {
                throw new InvalidTargetException($host);
            }
            $wire .= chr($length).$label;
        }

        if ($wire === '') {
            throw new InvalidTargetException($host);
        }

        $header = pack('nnnnnn', $id ?? random_int(0, 0xFFFF), 0x0100, 1, 0, 0, 0);

        return $header.$wire.pack('nn', $qtype, 1);
    }

    /**
     * @return DnsAnswer|null null = malformed/truncated-beyond-repair message
     */
    public static function decodeResponse(string $bytes): ?DnsAnswer
    {
        if (strlen($bytes) < self::HEADER_BYTES) {
            return null;
        }

        /** @var array{1: int, 2: int, 3: int, 4: int, 5: int} $header */
        $header = unpack('nid/nflags/nqdcount/nancount/nnscount/narcount', substr($bytes, 0, self::HEADER_BYTES));

        $flags = $header['flags'];
        if (($flags >> 15) !== 1) { // QR bit — must be a response
            return null;
        }

        $offset = self::HEADER_BYTES;
        for ($i = 0; $i < $header['qdcount']; $i++) {
            if (! self::skipName($bytes, $offset)) {
                return null;
            }
            $offset += 4;
        }

        $records = [];
        $ttls = [];
        $total = min(self::MAX_POINTER_JUMPS * 16, $header['ancount'] + $header['nscount'] + $header['arcount']);
        $parsed = 0;
        while ($parsed < $total && $offset + 10 <= strlen($bytes)) {
            if (! self::skipName($bytes, $offset)) {
                break;
            }
            if ($offset + 10 > strlen($bytes)) {
                break;
            }

            /** @var array{1: int, 2: int, 3: int, 4: int} $meta */
            $meta = unpack('ntype/nclass/Nttl/nrdlength', substr($bytes, $offset, 10));
            $offset += 10;

            $rdata = substr($bytes, $offset, $meta['rdlength']);
            if (strlen($rdata) < $meta['rdlength']) {
                break; // truncated tail — keep what parsed so far
            }
            $offset += $meta['rdlength'];
            $parsed++;

            $typeName = self::typeName($meta['type']);
            $value = match ($meta['type']) {
                1 => self::parseA($rdata),
                28 => self::parseAaaa($rdata),
                2, 5, 12 => self::readName($bytes, $offset - $meta['rdlength']),
                15 => self::parseMx($bytes, $offset - $meta['rdlength']),
                16 => self::parseTxt($rdata),
                6 => self::parseSoa($bytes, $offset - $meta['rdlength'], $meta['rdlength']),
                257 => self::parseCaa($rdata),
                48 => self::parseDnskey($rdata),
                43 => self::parseDs($rdata),
                default => null,
            };

            if ($typeName === null || $value === null || $value === '') {
                continue;
            }

            $records[$typeName][] = $value;
            $ttls[$typeName] = min($ttls[$typeName] ?? PHP_INT_MAX, $meta['ttl']);
        }

        return new DnsAnswer(
            rcode: $flags & 0x000F,
            authoritative: (($flags >> 10) & 1) === 1,
            dnssecAd: (($flags >> 5) & 1) === 1,
            records: $records,
            ttls: array_map(intval(...), $ttls),
            truncated: (($flags >> 9) & 1) === 1,
        );
    }

    private static function typeName(int $type): ?string
    {
        foreach (self::TYPES as $name => $code) {
            if ($code === $type) {
                return $name;
            }
        }

        return null;
    }

    private static function parseA(string $rdata): ?string
    {
        return strlen($rdata) === 4 ? long2ip(unpack('N', $rdata)[1]) : null;
    }

    private static function parseAaaa(string $rdata): ?string
    {
        if (strlen($rdata) !== 16) {
            return null;
        }

        $compressed = @inet_ntop($rdata);

        return $compressed === false ? null : $compressed;
    }

    private static function parseMx(string $bytes, int $rdataOffset): ?string
    {
        if (! isset($bytes[$rdataOffset + 1])) {
            return null;
        }

        $preference = unpack('n', substr($bytes, $rdataOffset, 2))[1];
        $exchange = self::readName($bytes, $rdataOffset + 2);

        return $exchange === null ? null : $preference.' '.$exchange;
    }

    private static function parseTxt(string $rdata): ?string
    {
        $strings = [];
        $offset = 0;
        while ($offset < strlen($rdata)) {
            $length = ord($rdata[$offset]);
            $strings[] = substr($rdata, $offset + 1, $length);
            $offset += 1 + $length;
        }

        return implode('', $strings);
    }

    private static function parseSoa(string $bytes, int $rdataOffset, int $rdLength): ?string
    {
        $afterMname = self::advanceName($bytes, $rdataOffset);
        if ($afterMname === null) {
            return null;
        }
        $mname = self::readName($bytes, $rdataOffset);

        $afterRname = self::advanceName($bytes, $afterMname);
        if ($mname === null || $afterRname === null || $afterRname + 20 > $rdataOffset + $rdLength) {
            return null;
        }
        $rname = self::readName($bytes, $afterMname);

        /** @var array{serial: int, refresh: int, retry: int, expire: int, minimum: int} $timers */
        $timers = unpack('Nserial/Nrefresh/Nretry/Nexpire/Nminimum', substr($bytes, $afterRname, 20));

        return "{$mname} {$rname} serial={$timers['serial']} refresh={$timers['refresh']} retry={$timers['retry']} expire={$timers['expire']} minimum={$timers['minimum']}";
    }

    private static function parseCaa(string $rdata): ?string
    {
        if (strlen($rdata) < 2) {
            return null;
        }

        $tagLength = ord($rdata[1]);
        if (strlen($rdata) < 2 + $tagLength) {
            return null;
        }

        $tag = substr($rdata, 2, $tagLength);
        $value = substr($rdata, 2 + $tagLength);

        return "$tag $value";
    }

    private static function parseDnskey(string $rdata): ?string
    {
        if (strlen($rdata) < 4) {
            return null;
        }

        /** @var array{1: int} $flags */
        [$flags] = array_values(unpack('n', substr($rdata, 0, 2)));
        $algorithm = ord($rdata[3]);

        return "alg=$algorithm flags=".sprintf('0x%04x', $flags).' key='.base64_encode(substr($rdata, 4));
    }

    private static function parseDs(string $rdata): ?string
    {
        if (strlen($rdata) < 4) {
            return null;
        }

        $keyTag = unpack('n', substr($rdata, 0, 2))[1];
        $algorithm = ord($rdata[2]);
        $digestType = ord($rdata[3]);

        return "keytag=$keyTag alg=$algorithm digesttype=$digestType digest=".strtoupper(bin2hex(substr($rdata, 4)));
    }

    /**
     * Reads a possibly-compressed name starting at $offset; returns null on
     * malformed input. Pointer jumps are guarded against loops.
     */
    private static function readName(string $bytes, int $offset): ?string
    {
        $labels = [];
        $totalBytes = 0;
        $jumps = 0;
        $cursor = $offset;
        $endCursor = null;

        while (true) {
            if (! isset($bytes[$cursor])) {
                return null;
            }

            $length = ord($bytes[$cursor]);

            if ($length === 0) {
                $endCursor ??= $cursor + 1;

                return $labels === [] ? '' : implode('.', $labels);
            }

            if ($length >= 0xC0) {
                if (! isset($bytes[$cursor + 1]) || ++$jumps > self::MAX_POINTER_JUMPS) {
                    return null;
                }
                if ($endCursor === null) {
                    $endCursor = $cursor + 2;
                }
                $cursor = (($length & 0x3F) << 8) | ord($bytes[$cursor + 1]);

                continue;
            }

            if ($length > 63) {
                return null;
            }

            $fragment = substr($bytes, $cursor + 1, $length);
            if (strlen($fragment) !== $length) {
                return null;
            }

            $totalBytes += $length + 1;
            if ($totalBytes > self::MAX_NAME_BYTES) {
                return null;
            }

            $labels[] = $fragment;
            $cursor += $length + 1;
        }
    }

    /** Advances past a name; false on malformed input. */
    private static function skipName(string $bytes, int &$offset): bool
    {
        $advanced = self::advanceName($bytes, $offset);
        if ($advanced === null) {
            return false;
        }
        $offset = $advanced;

        return true;
    }

    /** Offset just past the name at $offset; null on malformed input. */
    private static function advanceName(string $bytes, int $offset): ?int
    {
        while (true) {
            if (! isset($bytes[$offset])) {
                return null;
            }

            $length = ord($bytes[$offset]);

            if ($length === 0) {
                return $offset + 1;
            }

            if ($length >= 0xC0) {
                if (! isset($bytes[$offset + 1])) {
                    return null;
                }

                return $offset + 2;
            }

            if ($length > 63) {
                return null;
            }

            $offset += $length + 1;
        }
    }
}
