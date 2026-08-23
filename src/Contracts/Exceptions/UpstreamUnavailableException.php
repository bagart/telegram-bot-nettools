<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts\Exceptions;

/**
 * A source is down or rate-limited. Rendered as a warning line, never as a
 * hard error — partial results are never silent.
 */
final class UpstreamUnavailableException extends NettoolsException
{
    public function __construct(string $source, string $detail = '')
    {
        parent::__construct('upstream_unavailable', ['source' => $source], $detail !== '' ? $detail : "source unavailable: {$source}");
    }
}
