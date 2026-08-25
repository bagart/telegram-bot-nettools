<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\PingCard;

/**
 * /ping <host> (RFC §7.4): system ping (argv-safe) with TCP-connect timing
 * fallback; loss/min/avg/max/jitter + per-reply TTL. Never cached.
 * Weight 1.
 */
#[TgCommandAttribute(name: 'ping')]
final class PingCommand extends ProbeCommand
{
    public const string NAME = 'ping';

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->activeEnabled;
    }

    protected function probeFor(NetTarget $target): array
    {
        $s = $this->services;

        return [
            $s->pingProbe(),
            new ProbeOptions(timeoutSeconds: $s->settings->timeoutPing),
        ];
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        return PingCard::render($result, $chatId, time(), $hostLabel);
    }
}
