<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

/**
 * Raw port-43 query transport. Seam over stream sockets so the referral/
 * parsing logic stays testable without real network.
 */
interface Port43TransportContract
{
    /**
     * Single query/response round trip. null = connect/read failure, timeout
     * or empty answer — callers treat it as "source unavailable".
     */
    public function ask(string $server, string $query, int $timeoutSeconds): ?string;
}
