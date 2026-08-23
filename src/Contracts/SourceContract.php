<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts;

use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\SourcePayload;

/**
 * Upstream data provider behind a probe (RDAP server, CT log, mmdb, resolver).
 */
interface SourceContract
{
    /** Footer attribution name ("rdap", "crt.sh"). */
    public function name(): string;

    /** null = source unavailable → probe degrades with a visible warning. */
    public function fetch(NetTarget $target, ProbeOptions $options): ?SourcePayload;
}
