<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Probes\HttpProbe;
use BAGArt\TelegramBotNettools\Probes\SecHeadersProbe;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\SecCard;

/**
 * /sec <url|host> (RFC §7.8): security-headers audit + stack fingerprint +
 * security.txt; CORS/methods checks via flags (advanced actions later).
 * Weight 1.
 */
#[TgCommandAttribute(name: 'sec')]
final class SecCommand extends ProbeCommand
{
    public const string NAME = 'sec';

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->auditEnabled;
    }

    protected function probeFor(NetTarget $target): array
    {
        return [
            new SecHeadersProbe($this->services->fetcher),
            new ProbeOptions(
                flags: [
                    SecHeadersProbe::FLAG_CORS_CHECK => true,
                    SecHeadersProbe::FLAG_METHODS_CHECK => false,
                    HttpProbe::FLAG_SCHEME_HTTP => str_starts_with(strtolower($this->rawInput), 'http://'),
                ],
                timeoutSeconds: $this->effSettings->timeoutHttpFetch,
            ),
        ];
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        return SecCard::render($result, $chatId, time(), $hostLabel);
    }

    protected function parseArgs(string $argsRaw): string
    {
        $this->rawInput = trim($argsRaw);
        $host = parse_url($this->rawInput, PHP_URL_HOST) ?: $this->rawInput;

        return trim((string) $host);
    }

    private string $rawInput = '';
}
