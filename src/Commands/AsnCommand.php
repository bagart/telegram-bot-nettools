<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Probes\AsnProbe;
use BAGArt\TelegramBotNettools\Results\GuardVerdict;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\AsnCard;

/**
 * /asn <AS number|IP|domain> (RFC §7.15): org/registry/country, prefix
 * counts + sample, top peers by power, type classification. `AS15169`
 * bypasses the resolve pipeline (synthetic target). Weight 1.
 */
#[TgCommandAttribute(name: 'asn')]
final class AsnCommand extends ProbeCommand
{
    public const string NAME = 'asn';

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->reconEnabled;
    }

    protected function probeFor(NetTarget $target): array
    {
        $flags = $this->isAsnInput ? [AsnProbe::FLAG_ASN => true] : [];

        return [
            $this->services->asnProbe(),
            new ProbeOptions(flags: $flags, timeoutSeconds: 3),
        ];
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        return AsnCard::render($result, $chatId, time(), $hostLabel);
    }

    protected function syntheticTarget(string $rawInput): ?NetTarget
    {
        if (! preg_match('/^AS?(\d{1,10})$/i', trim($rawInput), $m)) {
            $this->isAsnInput = false;

            return null;
        }

        $this->isAsnInput = true;

        return new NetTarget(
            rawInput: 'AS'.$m[1],
            host: 'as'.$m[1],
            ips: [],
            isDomain: false,
            isIp: false,
            verdict: GuardVerdict::allow(),
        );
    }

    private bool $isAsnInput = false;
}
