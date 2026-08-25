<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Configs\TgBotConfig;
use BAGArt\TelegramBot\Contracts\Outbound\TgSenderContract;
use BAGArt\TelegramBot\Contracts\Processing\Processors\TgModuleProcessorContract;
use BAGArt\TelegramBot\Contracts\TgApi\TgApiTypeDTOContract;
use BAGArt\TelegramBot\Modules\Attributes\TgProcessorAttribute;
use BAGArt\TelegramBot\Modules\TgCommandRegistry;
use BAGArt\TelegramBot\Processing\BotProcessorContext;
use BAGArt\TelegramBot\Processing\ErrorHandling\ProcessorErrorContext;
use BAGArt\TelegramBot\TgApi\Types\DTO\MessageTypeDTO;
use BAGArt\TelegramBotNettools\Commands\Concerns\SendsCards;
use BAGArt\TelegramBotNettools\Formatters\Messages;
use BAGArt\TelegramBotNettools\NettoolsModule;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MainMenuKb;

/**
 * Completes two-step flows (RFC §3.6): when the bot is awaiting a target
 * (menu button "asked for input") and the user sends plain text (no slash
 * command), this processor re-dispatches it into the pending command.
 *
 * Registered as a bare MessageTypeDTO processor; support() is intentionally
 * narrow so it never steals real commands.
 */
#[TgProcessorAttribute(dto: MessageTypeDTO::class)]
final class FormContinuationProcessor implements TgModuleProcessorContract
{
    use SendsCards;

    public function __construct(
        private readonly TgSenderContract $sender,
        private readonly \BAGArt\TelegramBotNettools\NettoolsServices $services,
        private readonly BotProcessorContext $context,
    ) {
    }

    public static function moduleId(): string
    {
        return NettoolsModule::ID;
    }

    public static function build(BotProcessorContext $context): static
    {
        return new self(
            sender: $context->tgSender,
            services: \BAGArt\TelegramBotNettools\NettoolsServices::fromSetup($context->botSetup),
            context: $context,
        );
    }

    public function support(TgApiTypeDTOContract $dto, TgBotConfig $botConfig, ?string $action = null): bool
    {
        return $dto instanceof MessageTypeDTO
            && $dto->text !== null
            && ! str_starts_with(trim($dto->text), '/')
            && TgCommandRegistry::parseCommandName($dto->text) === null
            && $this->services->formState()->get((int) $dto->chat->id, $dto->from?->id) !== null;
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

        $chatId = (int) $dto->chat->id;
        $state = $this->services->formState()->get($chatId, $dto->from?->id);
        $this->services->formState()->clear($chatId, $dto->from?->id);

        $flow = is_array($state) ? ($state['flow'] ?? '') : '';
        $draft = is_array($state ?? null) ? ($state['draft'] ?? []) : [];

        if ($flow === 'target' && is_string($command = $draft['command'] ?? null)) {
            $class = CommandMap::byName($command);
            if ($class !== null) {
                $processor = new $class($this->sender, $this->services, $this->context);
                assert($processor instanceof ProbeCommand);
                $processor->execute($botConfig, (string) $chatId, $dto->from?->id, trim((string) $dto->text));

                return;
            }
        }

        // Expired/unknown flow degrades to menu re-entry — never a dead end
        $this->sendCard($botConfig, (string) $chatId, [
            'text' => Messages::format('awaiting_target'),
            'keyboard' => MainMenuKb::rows($chatId),
        ]);
    }

    public function onException(ProcessorErrorContext $context): void
    {
    }

}
