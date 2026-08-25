<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

/**
 * stream_socket_client port-43 transport (blocking, argv-safe — the query is
 * a normalized host, never raw user bytes beyond that). Bounded by the
 * caller's timeout on both connect and read.
 */
final class StreamPort43Transport implements Port43TransportContract
{
    private const int MAX_RESPONSE_BYTES = 16384;

    public function ask(string $server, string $query, int $timeoutSeconds): ?string
    {
        $errno = 0;
        $error = '';

        $socket = @stream_socket_client(
            'tcp://'.$server.':43',
            $errno,
            $error,
            $timeoutSeconds,
        );

        if ($socket === false) {
            return null;
        }

        try {
            stream_set_timeout($socket, $timeoutSeconds);

            if (@fwrite($socket, $query."\r\n") === false) {
                return null;
            }

            $buffer = '';
            while (! feof($socket)) {
                $chunk = fread($socket, 4096);
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $buffer .= $chunk;
                if (strlen($buffer) >= self::MAX_RESPONSE_BYTES) {
                    break;
                }
            }

            $timedOut = $this->timedOut($socket);
            if ($buffer === '' && $timedOut) {
                return null;
            }

            return trim($buffer);
        } finally {
            fclose($socket);
        }
    }

    private function timedOut(mixed $socket): bool
    {
        $meta = stream_get_meta_data($socket);

        return (bool) ($meta['timed_out'] ?? false);
    }
}
