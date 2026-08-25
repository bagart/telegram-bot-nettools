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
use BAGArt\TelegramBot\TgApi\Types\DTO\InlineKeyboardButtonTypeDTO;
use BAGArt\TelegramBot\TgApi\Types\DTO\InlineKeyboardMarkupTypeDTO;
use BAGArt\TelegramBot\TgApi\Types\DTO\MessageTypeDTO;
use BAGArt\TelegramBotNettools\Commands\Concerns\BuildsScreens;
use BAGArt\TelegramBotNettools\NettoolsModule;
use BAGArt\TelegramBotNettools\NettoolsServices;
use BAGArt\TelegramBotNettools\Ui\Button;

/**
 * /nt — menu hub: capabilities card with inline navigation; /nt help —
 * command catalog. Zero weight.
 *
 * Phase 0.5 spike: first production consumer of #[TgCommandAttribute].
 */
#[TgCommandAttribute(name: 'nt')]
final class NtCommand implements TgModuleProcessorContract
{
    use BuildsScreens;

    public const string NAME = 'nt';

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

        $chatId = (int) $dto->chat->id;
        $payload = trim(mb_substr((string) $dto->text, strlen(self::NAME) + 1));

        if (str_starts_with($payload, 'doctor')) {
            $this->sender->send($botConfig, new SendMessageMethodDTO(
                chatId: (string) $chatId,
                text: $this->services->quota->isAdminChat($chatId)
                    ? $this->doctorCardText()
                    : '🔒 /nt doctor is available in admin chats only.',
                parseMode: ParseModeEnum::HTML,
            ));

            return;
        }

        $card = match (true) {
            $payload === '', str_starts_with($payload, 'menu') => $this->menuCard($chatId),
            str_starts_with($payload, 'help') => $this->helpCard($chatId),
            default => null,
        };

        if ($card === null) {
            $this->sender->send($botConfig, new SendMessageMethodDTO(
                chatId: (string) $chatId,
                text: 'Unknown subcommand. Try /nt or /nt help.',
            ));

            return;
        }

        $this->sender->send($botConfig, new SendMessageMethodDTO(
            chatId: (string) $chatId,
            text: $card['text'],
            parseMode: ParseModeEnum::HTML,
            replyMarkup: self::keyboard($card['keyboard']),
        ));
    }

    /** /nt doctor — source health table (§3.2): capabilities + breaker states. */
    private function doctorCardText(): string
    {
        $lines = ['<b>NETTOOLS DOCTOR</b>', '', '<b>Capabilities</b>'];
        foreach ($this->services->capabilities->summaryLines() as $line) {
            $lines[] = '· '.htmlspecialchars($line, ENT_QUOTES);
        }

        $lines[] = '';
        $lines[] = '<b>Sources</b>';
        foreach (\BAGArt\TelegramBotNettools\Support\SourceBreaker::KNOWN_SOURCES as $source) {
            $state = $this->services->breaker?->stateOf($source) ?? 'closed';
            $icon = $state === 'open' ? '❌ open' : ($state === 'half-open' ? '🟡 half-open' : '✅ closed');
            $retry = $state !== 'closed' ? ' · retry in '.$this->services->breaker?->retryIn($source).'s' : '';
            $lines[] = '· '.str_pad(htmlspecialchars($source, ENT_QUOTES), 14).$icon.$retry;
        }

        return implode("
", $lines);
    }

    public function onException(ProcessorErrorContext $context): void
    {
    }

    /**
     * @param  list<list<Button>>  $keyboard
     */
    public static function keyboard(array $keyboard): InlineKeyboardMarkupTypeDTO
    {
        $rows = [];
        foreach ($keyboard as $row) {
            $buttons = [];
            foreach ($row as $button) {
                $buttons[] = new InlineKeyboardButtonTypeDTO(text: $button->text, callbackData: $button->callbackData);
            }
            $rows[] = $buttons;
        }

        return new InlineKeyboardMarkupTypeDTO(inlineKeyboard: $rows);
    }
}
