<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Probes\DnsProbe;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\Button;
use BAGArt\TelegramBotNettools\Ui\CallbackGrammar;
use BAGArt\TelegramBotNettools\Ui\DnsCard;

/**
 * /dns <domain> [type] (RFC §7.2): record matrix with TTLs, per-type
 * statuses, DNSSEC AD hint; [Propagation]/[Diagnostics] actions. Weight 1.
 */
#[TgCommandAttribute(name: 'dns')]
final class DnsCommand extends ProbeCommand
{
    public const string NAME = 'dns';

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->reconEnabled;
    }

    protected function usageKey(): string
    {
        return 'usage_dns';
    }

    protected function probeFor(NetTarget $target): array
    {
        return [
            $this->services->dnsProbe(),
            new ProbeOptions(
                flags: $this->recordType !== null ? [DnsProbe::FLAG_RECORD_TYPE => $this->recordType] : [],
                timeoutSeconds: $this->effSettings->timeoutDns,
            ),
        ];
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        $card = DnsCard::render($result, $chatId, time(), $hostLabel);

        if ($this->recordType === null) {
            $ref = $this->services->targetRef()->remember($hostLabel, '');
            $card['keyboard'][] = [
                new Button('🌐 Propagation', CallbackGrammar::encode('dnsprop', $chatId, $ref)),
                new Button('🩺 Diagnostics', CallbackGrammar::encode('dnsdiag', $chatId, $ref)),
            ];
        }

        return $card;
    }

    protected function parseArgs(string $argsRaw): string
    {
        [$target, $type] = array_pad(preg_split('/\s+/', trim($argsRaw)) ?: [], 2, '');
        $this->recordType = $type !== '' ? strtoupper($type) : null;

        return trim($target);
    }

    private ?string $recordType = null;
}
