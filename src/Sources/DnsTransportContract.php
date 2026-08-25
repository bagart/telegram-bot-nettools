<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

/**
 * Datagram seam for the internal DNS client (RFC D5): carries raw DNS message
 * bytes to/from a resolver endpoint. UDP asks may be truncated (TC bit — the
 * client retries over askTcp); TCP payloads include the 2-byte length prefix
 * framing handled here, callers always see bare message bytes.
 *
 * The server argument is an IPv4 resolver address, optionally suffixed with
 * ":port" to target non-standard endpoints (fixture servers); plain addresses
 * default to port 53.
 */
interface DnsTransportContract
{
    /** Single UDP exchange; null = network failure/timeout. */
    public function askUdp(string $serverIp, string $wireQuery, int $timeoutSeconds): ?string;

    /** Single TCP exchange (length-prefix framed); null = failure/timeout. */
    public function askTcp(string $serverIp, string $wireQuery, int $timeoutSeconds): ?string;
}
