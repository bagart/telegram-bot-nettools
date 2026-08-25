<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Configs\TgBotConfig;
use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBot\TgApi\Types\DTO\MessageTypeDTO;
use BAGArt\TelegramBotNettools\Formatting\Messages;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Probes\PortScanProbe;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Ui\Button;
use BAGArt\TelegramBotNettools\Ui\CallbackGrammar;
use BAGArt\TelegramBotNettools\Ui\PortScanCard;

/**
 * /portscan <host> (RFC §7.11): admin-gated TCP connect scan, top-100 ports.
 * Weight 10 + heavy-confirm. Denied for non-admin chats / disabled flag.
 */
#[TgCommandAttribute(name: 'portscan')]
final class PortscanCommand extends ProbeCommand
{
    public const string NAME = 'portscan';

    public const int WEIGHT = 10;

    protected ?string $currentChatId = null;

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->portscanEnabled && $this->services->quota->isAdminChat($this->currentChatId ?? '');
    }

    protected function probeFor(NetTarget $target): array
    {
        return [
            new PortScanProbe(maxPorts: 100),
            new ProbeOptions(timeoutSeconds: PortScanProbe::WALL_CAP_SECONDS),
        ];
    }

    protected function heavyCapSeconds(): ?int
    {
        return PortScanProbe::WALL_CAP_SECONDS;
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        return PortScanCard::render($result, $chatId, time(), $hostLabel);
    }

    public function execute(
        TgBotConfig $botConfig,
        string $chatId,
        int|string|null $userId,
        string $argsRaw,
        bool $confirmed = false,
        ?MessageTypeDTO $dto = null,
    ): void {
        $this->currentChatId = $chatId;

        if (! $this->services->settings->portscanEnabled || ! $this->services->quota->isAdminChat($chatId)) {
            $this->sendCard($botConfig, $chatId, [
                'text' => "🔒 /".self::NAME." is restricted to admin chats with the feature enabled.\n\n".
                    Messages::format('usage_target', ['command' => self::NAME]),
                'keyboard' => [[new Button('💰 Quota', CallbackGrammar::encode('quota', (int) $chatId))]],
            ]);

            return;
        }

        parent::execute($botConfig, $chatId, $userId, $argsRaw, $confirmed, $dto);
    }
}
