<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Configs\TgBotConfig;
use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBot\TgApi\Types\DTO\MessageTypeDTO;
use BAGArt\TelegramBotNettools\Formatting\Messages;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Probes\DnsblProbe;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Ui\Button;
use BAGArt\TelegramBotNettools\Ui\CallbackGrammar;
use BAGArt\TelegramBotNettools\Ui\DnsblCard;

/**
 * /dnsbl <ip> (RFC §7.12): admin-gated DNSBL listing check across ~10 zones.
 * Weight 2.
 */
#[TgCommandAttribute(name: 'dnsbl')]
final class DnsblCommand extends ProbeCommand
{
    public const string NAME = 'dnsbl';

    public const int WEIGHT = 2;

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->dnsblEnabled && $this->services->quota->isAdminChat($this->currentChat ?? '');
    }

    protected ?string $currentChat = null;

    protected function probeFor(NetTarget $target): array
    {
        return [
            new DnsblProbe(
                dns: new DnsClient($this->services->dnsTransport),
                resolvers: $this->services->resolvers(),
                timeoutSeconds: $this->effSettings->timeoutDns,
                breaker: $this->services->breaker,
            ),
            new ProbeOptions(timeoutSeconds: 3),
        ];
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        return DnsblCard::render($result, $chatId, time(), $hostLabel);
    }

    public function execute(
        TgBotConfig $botConfig,
        string $chatId,
        int|string|null $userId,
        string $argsRaw,
        bool $confirmed = false,
        ?MessageTypeDTO $dto = null,
    ): void {
        $this->currentChat = $chatId;

        if (! $this->services->settings->dnsblEnabled || ! $this->services->quota->isAdminChat($chatId)) {
            $this->sendCard($botConfig, $chatId, [
                'text' => Messages::format('admin_gate_denied', [
                    'command' => self::NAME,
                    'usage' => Messages::format('usage_target', ['command' => self::NAME]),
                ]),
                'keyboard' => [[new Button('💰 Quota', CallbackGrammar::encode('quota', (int) $chatId))]],
            ]);

            return;
        }

        parent::execute($botConfig, $chatId, $userId, $argsRaw, $confirmed, $dto);
    }
}
