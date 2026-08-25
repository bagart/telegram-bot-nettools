<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Configs\TgBotConfig;
use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBot\Modules\TgCommandRegistry;
use BAGArt\TelegramBot\TgApi\Types\DTO\MessageTypeDTO;
use BAGArt\TelegramBotNettools\Commands\Concerns\SendsCards;
use BAGArt\TelegramBotNettools\Formatting\Messages;
use BAGArt\TelegramBotNettools\NettoolsModule;

/**
 * /r — repeat the last nettools command in this chat (RFC §3.1 "again!").
 * Zero-weight itself; re-charges whatever it repeats by delegating to the
 * original command class with the stored raw args.
 */
#[TgCommandAttribute(name: 'r')]
final class RepeatCommand implements \BAGArt\TelegramBot\Contracts\Processing\Processors\TgModuleProcessorContract
{
    use SendsCards;

    public const string NAME = 'r';

    public function __construct(
        private readonly \BAGArt\TelegramBot\Contracts\Outbound\TgSenderContract $sender,
        private readonly \BAGArt\TelegramBotNettools\NettoolsServices $services,
        private readonly \BAGArt\TelegramBot\Processing\BotProcessorContext $context,
    ) {
    }

    public static function moduleId(): string
    {
        return NettoolsModule::ID;
    }

    public static function build(\BAGArt\TelegramBot\Processing\BotProcessorContext $context): static
    {
        return new self($context->tgSender, \BAGArt\TelegramBotNettools\NettoolsServices::fromSetup($context->botSetup), $context);
    }

    public function support(
        \BAGArt\TelegramBot\Contracts\TgApi\TgApiTypeDTOContract $dto,
        TgBotConfig $botConfig,
        ?string $action = null,
    ): bool {
        return $dto instanceof MessageTypeDTO
            && $dto->text !== null
            && TgCommandRegistry::parseCommandName($dto->text) === self::NAME;
    }

    public function isStrictOrdered(
        \BAGArt\TelegramBot\Contracts\TgApi\TgApiTypeDTOContract $dto,
        TgBotConfig $botConfig,
        ?string $action = null,
    ): bool {
        return false;
    }

    public function process(
        \BAGArt\TelegramBot\Contracts\TgApi\TgApiTypeDTOContract $dto,
        TgBotConfig $botConfig,
        ?string $action = null,
        ?\BAGArt\TelegramBot\Contracts\TgApi\TgApiTypeDTOContract $updateDto = null,
    ): void {
        assert($dto instanceof MessageTypeDTO);

        $chatId = (string) $dto->chat->id;
        $last = $this->services->lastAction()->recall($chatId);

        if ($last === null || CommandMap::byName((string) $last['command']) === null) {
            $this->sendCard($botConfig, $chatId, [
                'text' => Messages::format('repeat_empty'),
                'keyboard' => [],
            ]);

            return;
        }

        $class = CommandMap::byName((string) $last['command']);
        assert($class !== null);
        $command = new $class($this->sender, $this->services, $this->context);
        assert($command instanceof ProbeCommand);
        $command->execute($botConfig, $chatId, $dto->from?->id, $last['args']);
    }

    public function onException(\BAGArt\TelegramBot\Processing\ErrorHandling\ProcessorErrorContext $context): void
    {
    }
}
