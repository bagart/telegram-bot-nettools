<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Configs\TgBotConfig;
use BAGArt\TelegramBot\Contracts\Outbound\TgSenderContract;
use BAGArt\TelegramBot\Contracts\Processing\Processors\TgModuleProcessorContract;
use BAGArt\TelegramBot\Contracts\TgApi\TgApiTypeDTOContract;
use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBot\Modules\TgCommandRegistry;
use BAGArt\TelegramBot\Processing\BotProcessorContext;
use BAGArt\TelegramBot\Processing\ErrorHandling\ProcessorErrorContext;
use BAGArt\TelegramBot\TgApi\Methods\DTO\SendMessageMethodDTO;
use BAGArt\TelegramBot\TgApi\Methods\Enum\ParseModeEnum;
use BAGArt\TelegramBot\TgApi\Types\DTO\MessageTypeDTO;
use BAGArt\TelegramBotNettools\NettoolsModule;
use BAGArt\TelegramBotNettools\NettoolsServices;
use BAGArt\TelegramBotNettools\Ui\QuotaCard;

/**
 * /quota — caller's remaining budget in this chat. Zero weight.
 */
#[TgCommandAttribute(name: 'quota')]
final class QuotaCommand implements TgModuleProcessorContract
{
    public const string NAME = 'quota';

    public function __construct(
        private readonly TgSenderContract $sender,
        private readonly NettoolsServices $services,
    ) {
    }

    public static function moduleId(): string
    {
        return NettoolsModule::ID;
    }

    public static function build(BotProcessorContext $context): self
    {
        return new self(
            sender: $context->tgSender,
            services: NettoolsServices::fromSetup($context->botSetup),
        );
    }

    public function support(TgApiTypeDTOContract $dto, TgBotConfig $botConfig, ?string $action = null): bool
    {
        return $dto instanceof MessageTypeDTO
            && $dto->text !== null
            && TgCommandRegistry::parseCommandName($dto->text) === self::NAME;
    }

    public function isStrictOrdered(TgApiTypeDTOContract $dto, TgBotConfig $botConfig, ?string $action = null): bool
    {
        return false;
    }

    public function process(
        TgApiTypeDTOContract $dto,
        TgBotConfig $botConfig,
        ?string $action = null,
        ?TgApiTypeDTOContract $updateDto = null,
    ): void {
        assert($dto instanceof MessageTypeDTO);

        $chatId = (string) $dto->chat->id;
        $userId = $dto->from !== null ? $dto->from->id : null;

        $card = QuotaCard::render($this->services->quota, $chatId, $userId);

        $this->sender->send($botConfig, new SendMessageMethodDTO(
            chatId: $chatId,
            text: $card['text'],
            parseMode: ParseModeEnum::HTML,
        ));
    }

    public function onException(ProcessorErrorContext $context): void
    {
    }
}
