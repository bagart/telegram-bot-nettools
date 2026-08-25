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
use BAGArt\TelegramBot\TgApi\Types\DTO\MessageTypeDTO;
use BAGArt\TelegramBotNettools\Commands\Concerns\SendsCards;
use BAGArt\TelegramBotNettools\Ui\CallbackGrammar;
use BAGArt\TelegramBotNettools\Ui\Keyboards\TargetContextKb;
use BAGArt\TelegramBotNettools\Ui\MyCard;

/**
 * /my — remembered targets (RFC §3.7): pinned/recent list; tapping a row's
 * number opens the habit-ranked context menu for that host.
 */
#[TgCommandAttribute(name: 'my')]
final class MyCommand implements TgModuleProcessorContract
{
    use SendsCards;

    public const string NAME = 'my';

    private const array CONTEXT_PROBES = ['report', 'reco', 'whois', 'dns', 'ssl', 'sec', 'ping', 'ip', 'trace'];

    public function __construct(
        private readonly TgSenderContract $sender,
        private readonly \BAGArt\TelegramBotNettools\NettoolsServices $services,
    ) {
    }

    public static function moduleId(): string
    {
        return \BAGArt\TelegramBotNettools\NettoolsModule::ID;
    }

    public static function build(BotProcessorContext $context): self
    {
        return new self($context->tgSender, \BAGArt\TelegramBotNettools\NettoolsServices::fromSetup($context->botSetup));
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

        $this->sendCard($botConfig, (string) $dto->chat->id, $this->listCard((int) ($dto->from?->id ?? 0), (int) $dto->chat->id));
    }

    /** @return array{text: string, keyboard: list<list<\BAGArt\TelegramBotNettools\Ui\Button>>} */
    public function listCard(int $userId, int $chatId): array
    {
        $targets = $this->services->memory()->list($userId);

        usort($targets, static fn (array $a, array $b): int => [(bool) $b['pinned'], ($a['last_used_at'] ?? 0)]
            <=> [(bool) $a['pinned'], ($b['last_used_at'] ?? 0)]);

        $refs = [];
        foreach (array_slice($targets, 0, 9) as $i => $row) {
            $refs[$i] = CallbackGrammar::encode(
                'ctx',
                $chatId,
                $this->services->targetRef()->remember((string) $row['host'], '')
            );
        }

        return MyCard::render(
            $chatId,
            $targets,
            $this->services->settings->autoCapture,
            $this->services->settings->maxTargets,
            $refs,
        );
    }

    /** Habit-ranked target context menu for the router ('ctx' action). */
    public function contextCard(int $userId, int $chatId, string $host): array
    {
        $ranked = $this->services->memory()->rankedProbes(
            $userId,
            $host,
            array_values(array_intersect(self::CONTEXT_PROBES, array_keys(CommandMap::MAP))),
        );

        $buttons = [];
        foreach ($ranked as $command) {
            $class = CommandMap::byName($command);
            if ($class === null) {
                continue;
            }
            $buttons[] = ['label' => $command, 'data' => CallbackGrammar::encode(
                'go',
                $chatId,
                $this->services->targetRef()->remember($host, $command)
            )];
        }

        $pinned = false;
        foreach ($this->services->memory()->list($userId) as $row) {
            if (strcasecmp((string) $row['host'], $host) === 0) {
                $pinned = (bool) $row['pinned'];
                break;
            }
        }

        return [
            'text' => '<b>🎯 '.htmlspecialchars($host, ENT_QUOTES).'</b>',
            'keyboard' => TargetContextKb::rows(
                $chatId,
                $buttons,
                $this->services->targetRef()->remember($host, ''),
                $pinned,
            ),
        ];
    }
}
