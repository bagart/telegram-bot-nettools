<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Probes\HttpProbe;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\HttpCard;

/**
 * /http <url|host> (RFC §7.13): availability & speed snapshot — status,
 * redirect chain with per-hop timing, size/compression, server banner.
 * Weight 1.
 */
#[TgCommandAttribute(name: 'http')]
final class HttpCommand extends ProbeCommand
{
    public const string NAME = 'http';

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->reconEnabled;
    }

    protected function probeFor(NetTarget $target): array
    {
        $schemeFlag = str_starts_with(strtolower($this->lastInput), 'http://')
            ? [HttpProbe::FLAG_SCHEME_HTTP => true]
            : [];

        return [
            $this->services->httpProbe(),
            new ProbeOptions(
                flags: $schemeFlag,
                timeoutSeconds: $this->effSettings->timeoutHttpFetch,
            ),
        ];
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        return HttpCard::render($result, $chatId, time(), $hostLabel);
    }

    protected function parseArgs(string $argsRaw): string
    {
        $this->lastInput = trim($argsRaw);

        return trim(parse_url($this->lastInput, PHP_URL_HOST) ?: $this->lastInput);
    }

    private string $lastInput = '';
}
