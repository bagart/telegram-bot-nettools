<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Probes\SubsProbe;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Sources\CtLogSource;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Ui\SubsCard;

/**
 * /subs <domain> (RFC §7.6): passive CT-log enumeration with wildcard
 * detection; wordlist brute-force is opt-in via the FLAG_BRUTE option
 * ([Re-run with wordlist] action), never on by default. Weight 3.
 */
#[TgCommandAttribute(name: 'subs')]
final class SubsCommand extends ProbeCommand
{
    public const string NAME = 'subs';

    public const int WEIGHT = 3;

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->auditEnabled;
    }

    protected function usageKey(): string
    {
        return 'usage_target';
    }

    protected function probeFor(NetTarget $target): array
    {
        unset($target);

        return [
            new SubsProbe(
                new CtLogSource($this->services->http),
                new DnsClient($this->services->dnsTransport),
                $this->resolvers(),
                $this->effSettings->timeoutDns,
            ),
            new ProbeOptions(flags: [SubsProbe::FLAG_BRUTE => false], timeoutSeconds: 10),
        ];
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        return SubsCard::render($result, $chatId, time(), $hostLabel);
    }

    /**
     * NettoolsServices::resolvers() is private to the service bundle, so the
     * same config read + normalization is mirrored here until it is exposed.
     *
     * @return list<string>
     */
    private function resolvers(): array
    {
        try {
            return array_values(array_filter(array_map(strval(...), (array) config('tg-nettools.resolvers', ['1.1.1.1', '8.8.8.8']))));
        } catch (\Throwable) {
            return ['1.1.1.1', '8.8.8.8'];
        }
    }
}
