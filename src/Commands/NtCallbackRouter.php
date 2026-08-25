<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Configs\TgBotConfig;
use BAGArt\TelegramBot\Contracts\Outbound\TgSenderContract;
use BAGArt\TelegramBot\Contracts\Processing\Processors\TgModuleProcessorContract;
use BAGArt\TelegramBot\Contracts\TgApi\TgApiTypeDTOContract;
use BAGArt\TelegramBot\Modules\Attributes\TgProcessorAttribute;
use BAGArt\TelegramBot\Processing\BotProcessorContext;
use BAGArt\TelegramBot\Processing\ErrorHandling\ProcessorErrorContext;
use BAGArt\TelegramBot\TgApi\Methods\DTO\AnswerCallbackQueryMethodDTO;
use BAGArt\TelegramBot\TgApi\Methods\DTO\SendMessageMethodDTO;
use BAGArt\TelegramBot\TgApi\Types\DTO\CallbackQueryTypeDTO;
use BAGArt\TelegramBot\TgApi\Types\DTO\InlineKeyboardButtonTypeDTO;
use BAGArt\TelegramBot\TgApi\Types\DTO\InlineKeyboardMarkupTypeDTO;
use BAGArt\TelegramBotNettools\Commands\Concerns\BuildsScreens;
use BAGArt\TelegramBotNettools\NettoolsModule;
use BAGArt\TelegramBotNettools\NettoolsServices;
use BAGArt\TelegramBotNettools\Ui\Button;
use BAGArt\TelegramBotNettools\Ui\CallbackGrammar;
use BAGArt\TelegramBotNettools\Ui\QuotaCard;

/**
 * Routes every "nt:v1:*" inline callback (RFC §3.6). The parsed CallbackQuery
 * DTO carries no usable originating-message id, so screens are delivered as
 * fresh messages (summarizer precedent); the query itself is always answered.
 *
 * Unknown/evicted actions degrade to the main menu — never a dead end.
 */
#[TgProcessorAttribute(dto: CallbackQueryTypeDTO::class)]
final class NtCallbackRouter implements TgModuleProcessorContract
{
    use BuildsScreens;

    /** World ping wall budget: create ≤5s + 5 polls ×(1s sleep + ≤5s fetch). */
    private const int WORLD_PING_CAP_SECONDS = 35;

    public function __construct(
        private readonly TgSenderContract $sender,
        private readonly NettoolsServices $services,
        private readonly BotProcessorContext $context,
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
            context: $context,
        );
    }

    public function support(TgApiTypeDTOContract $dto, TgBotConfig $botConfig, ?string $action = null): bool
    {
        return $dto instanceof CallbackQueryTypeDTO
            && str_starts_with((string) ($dto->data ?? ''), CallbackGrammar::PREFIX);
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
        assert($dto instanceof CallbackQueryTypeDTO);

        $route = CallbackGrammar::decode($dto->data);
        if ($route === null) {
            $this->answer($botConfig, $dto, 'Unknown or expired action.');

            return;
        }

        $chatId = (string) $route['chatId'];

        switch ($route['action']) {
            case 'menu':
            case 'status':
                $card = $this->menuCard($route['chatId']);
                break;

            case 'tools':
                $this->answer($botConfig, $dto);
                $this->sendCard($botConfig, $chatId, \BAGArt\TelegramBotNettools\Ui\NtCards::tools($route['chatId']));
                return;

            case 'ask':
                // Two-step form (§3.6): remember the requested tool and ask
                // for the target. The next plain-text message completes it.
                $command = self::decodeAskRef($route['ref']);
                if ($command !== null && CommandMap::byName($command) !== null) {
                    $this->services->formState()->set($chatId, $dto->from?->id, [
                        'flow' => 'target',
                        'step' => 'await_target',
                        'draft' => ['command' => $command],
                    ]);
                    $this->answer($botConfig, $dto, '/'.$command.' — send the target now.');
                    $this->sendCard($botConfig, $chatId, [
                        'text' => '🎯 <b>/'.$command.'</b> — send the target now (domain or IP).',
                        'keyboard' => [[new Button('✖ Cancel', CallbackGrammar::encode('cancel', $route['chatId']))]],
                    ]);
                    return;
                }
                $card = $this->menuCard($route['chatId']);
                break;

            case 'help':
                $card = $this->helpCard($route['chatId']);
                break;

            case 'quota':
                $card = QuotaCard::render($this->services->quota, $route['chatId'], (int) ($dto->from->id ?? 0));
                break;

            case 'cancel':
                // Heavy-op confirmation declined; nothing charged, form dropped.
                $this->services->formState()->clear($chatId, $dto->from?->id);
                $this->answer($botConfig, $dto, 'Cancelled.');

                return;

            case 'go':
                if ($this->runConfirmed($route['ref'], $chatId, $dto, $botConfig)) {
                    return;
                }
                $card = $this->menuCard($route['chatId']);
                break;

            case 'my':
            case 'ctx':
            case 'pin':
            case 'unpin':
            case 'forget':
            case 'clear':
            case 'settings':
            case 'set_heavy':
            case 'set_autosave':
            case 'dnsprop':
            case 'dnsdiag':
            case 'wping':
            case 'mailsmtp':
                if (($handled = $this->extended($route, $dto, $botConfig)) !== null) {
                    if ($handled) {
                        return;
                    }
                }
                $card = $this->menuCard($route['chatId']);
                break;

            default:
                // Unknown/evicted ref → graceful menu re-entry
                $this->answer($botConfig, $dto, 'Unknown action — back to the menu.');
                $this->sendCard($botConfig, $chatId, $this->menuCard($route['chatId']));

                return;
        }

        $this->answer($botConfig, $dto);
        $this->sendCard($botConfig, $chatId, $card);
    }

    public function onException(ProcessorErrorContext $context): void
    {
    }

    /**
     * Extended actions (memory / settings / dns diagnostics / world ping /
     * smtp check). Return true = fully handled (message already sent),
     * false/null = fall back to menu.
     */
    /** 'h'+10hex of 'ask|{command}' → command name (pure, no cache). */
    private static function decodeAskRef(string $ref): ?string
    {
        foreach (CommandMap::MAP as $name => $_) {
            if ('h'.substr(hash('sha256', 'ask|'.$name), 0, 10) === $ref) {
                return $name;
            }
        }

        return null;
    }

    private function extended(array $route, CallbackQueryTypeDTO $dto, TgBotConfig $botConfig): ?bool
    {
        $chatId = (string) $route['chatId'];
        $userId = (int) ($dto->from->id ?? 0);
        $my = new MyCommand($this->sender, $this->services);

        switch ($route['action']) {
            case 'my':
                $this->sendCard($botConfig, $chatId, $my->listCard($userId, $route['chatId']));
                $this->answer($botConfig, $dto);
                return true;

            case 'ctx':
                $host = $this->services->targetRef()->resolve($route['ref'])['host'] ?? null;
                if (! is_string($host)) {
                    $this->answer($botConfig, $dto, 'Target forgotten — pick again.');
                    return false;
                }
                $this->sendCard($botConfig, $chatId, $my->contextCard($userId, $route['chatId'], $host));
                $this->answer($botConfig, $dto);
                return true;

            case 'pin':
            case 'unpin':
                $entry = $this->services->targetRef()->resolve($route['ref']);
                if ($entry !== null) {
                    $this->services->memory()->pin($userId, $entry['host'], $route['action'] === 'pin');
                    $this->answer($botConfig, $dto, $route['action'] === 'pin' ? 'Pinned ⭐' : 'Unpinned');
                    $this->sendCard($botConfig, $chatId, $my->listCard($userId, $route['chatId']));
                    return true;
                }
                $this->answer($botConfig, $dto, 'Target forgotten.');
                return false;

            case 'forget':
                $entry = $this->services->targetRef()->resolve($route['ref']);
                if ($entry !== null) {
                    $this->services->memory()->forget($userId, $entry['host']);
                    $this->answer($botConfig, $dto, 'Forgotten 🗑');
                    $this->sendCard($botConfig, $chatId, $my->listCard($userId, $route['chatId']));
                    return true;
                }
                $this->answer($botConfig, $dto, 'Target forgotten.');
                return false;

            case 'clear':
                $this->services->memory()->clearAll($userId);
                $this->answer($botConfig, $dto, 'All targets cleared 🧹');
                $this->sendCard($botConfig, $chatId, $my->listCard($userId, $route['chatId']));
                return true;

            case 'settings':
                $this->sendCard(
                    $botConfig,
                    $chatId,
                    \BAGArt\TelegramBotNettools\Ui\NtCards::settings($route['chatId'], $this->services->chatSettings()->raw($chatId))
                );
                $this->answer($botConfig, $dto);
                return true;

            case 'set_heavy':
                $current = $this->services->chatSettings()->raw($chatId)['heavy_confirm']
                    ?? $this->services->settings->heavyConfirm;
                $this->services->chatSettings()->setHeavyConfirm($chatId, ! (bool) $current);
                $this->sendCard(
                    $botConfig,
                    $chatId,
                    \BAGArt\TelegramBotNettools\Ui\NtCards::settings($route['chatId'], $this->services->chatSettings()->raw($chatId))
                );
                $this->answer($botConfig, $dto, 'Toggled.');
                return true;

            case 'set_autosave':
                $current = $this->services->chatSettings()->raw($chatId)['auto_capture']
                    ?? $this->services->settings->autoCapture;
                $this->services->chatSettings()->setAutoCapture($chatId, ! (bool) $current);
                $this->sendCard(
                    $botConfig,
                    $chatId,
                    \BAGArt\TelegramBotNettools\Ui\NtCards::settings($route['chatId'], $this->services->chatSettings()->raw($chatId))
                );
                $this->answer($botConfig, $dto, 'Toggled.');
                return true;

            case 'dnsprop':
                return $this->runDnsDiagnostics($route, $dto, $botConfig, propagation: true);

            case 'dnsdiag':
                return $this->runDnsDiagnostics($route, $dto, $botConfig, propagation: false);

            case 'wping':
                return $this->runWorldPing($route, $dto, $botConfig, $chatId);

            case 'mailsmtp':
                return $this->runSmtpCheck($route, $dto, $botConfig, $chatId);
        }

        return null;
    }

    private function runDnsDiagnostics(array $route, CallbackQueryTypeDTO $dto, TgBotConfig $botConfig, bool $propagation): bool
    {
        $entry = $this->services->targetRef()->resolve($route['ref']);
        if ($entry === null) {
            $this->answer($botConfig, $dto, 'Target forgotten — pick again.');
            return false;
        }

        $diagnostics = new \BAGArt\TelegramBotNettools\Support\DnsDiagnostics(
            new \BAGArt\TelegramBotNettools\Sources\DnsClient($this->services->dnsTransport),
            $this->services->resolvers(),
        );
        $result = $propagation
            ? $diagnostics->propagation($entry['host'])
            : $diagnostics->lameAndOpen($entry['host']);

        $this->answer($botConfig, $dto);
        $this->sendCard($botConfig, (string) $route['chatId'], [
            'text' => $propagation
                ? \BAGArt\TelegramBotNettools\Ui\DnsPropagationCard::render($result)
                : \BAGArt\TelegramBotNettools\Ui\DnsDiagnosticsCard::render($result),
            'keyboard' => [[new \BAGArt\TelegramBotNettools\Ui\Button('« Menu', \BAGArt\TelegramBotNettools\Ui\CallbackGrammar::encode('menu', $route['chatId']))]],
        ]);

        return true;
    }

    private function runWorldPing(array $route, CallbackQueryTypeDTO $dto, TgBotConfig $botConfig, string $chatId): bool
    {
        $entry = $this->services->targetRef()->resolve($route['ref']);
        if ($entry === null) {
            $this->answer($botConfig, $dto, 'Target forgotten — pick again.');
            return false;
        }

        // Heavy slot before the rate slot: a busy rejection must not consume
        // the caller's once-per-minute budget.
        try {
            $this->services->semaphore->acquire(self::WORLD_PING_CAP_SECONDS);
            $this->services->metrics()->recordEvent('heavy_acquired');
        } catch (\BAGArt\TelegramBotNettools\Contracts\Exceptions\SemaphoreBusyException $exception) {
            $this->services->metrics()->recordEvent('semaphore_busy');
            $this->answer($botConfig, $dto, $exception->userMessage());
            return true;
        }

        try {
            if (! $this->services->rateLimiter()->hit('worldping', $chatId, $dto->from?->id, 1, 60)) {
                $this->answer($botConfig, $dto, 'World ping: max 1 per minute — try later.');
                return true;
            }

            $world = new \BAGArt\TelegramBotNettools\Support\WorldPing($this->services->fetcher);
            $outcome = $world->ping($entry['host']);

            $this->answer($botConfig, $dto);
            $this->sendCard($botConfig, $chatId, [
                'text' => \BAGArt\TelegramBotNettools\Ui\WorldPingCard::render($outcome, $entry['host']),
                'keyboard' => [[new \BAGArt\TelegramBotNettools\Ui\Button('« Menu', \BAGArt\TelegramBotNettools\Ui\CallbackGrammar::encode('menu', $route['chatId']))]],
            ]);
        } finally {
            $this->services->semaphore->release();
        }

        return true;
    }

    private function runSmtpCheck(array $route, CallbackQueryTypeDTO $dto, TgBotConfig $botConfig, string $chatId): bool
    {
        $entry = $this->services->targetRef()->resolve($route['ref']);
        if ($entry === null || $entry['command'] !== MailCommand::NAME) {
            $this->answer($botConfig, $dto, 'Run /mail first, then use its SMTP check.');
            return false;
        }

        $command = MailCommand::class;
        $processor = $command::build($this->context);
        assert($processor instanceof MailCommand);
        $this->answer($botConfig, $dto, 'SMTP check running…');
        $processor->execute($botConfig, $chatId, $dto->from?->id, '--smtp '.$entry['host'], confirmed: true);

        return true;
    }

    /**
     * Heavy-confirm [Run]: resolve ref → command + host, execute confirmed.
     * Double-tap safe: the form state clears before the probe starts, so a
     * second tap finds nothing and just answers.
     */
    private function runConfirmed(string $ref, string $chatId, CallbackQueryTypeDTO $dto, TgBotConfig $botConfig): bool
    {
        $entry = $this->services->targetRef()->resolve($ref);
        if ($entry === null) {
            $this->answer($botConfig, $dto, 'Target forgotten — pick again.');

            return false;
        }

        $class = CommandMap::byName($entry['command']);
        if ($class === null) {
            $this->answer($botConfig, $dto, 'Command unavailable.');

            return false;
        }

        $this->services->formState()->clear($chatId, $dto->from?->id);
        $this->answer($botConfig, $dto, 'Running…');

        $command = new $class($this->sender, $this->services, $this->context);
        assert($command instanceof ProbeCommand);
        $command->execute($botConfig, $chatId, $dto->from?->id, $entry['host'], confirmed: true);

        return true;
    }

    /**
     * @param  array{text: string, keyboard: list<list<Button>>}  $card
     */
    private function sendCard(TgBotConfig $botConfig, string $chatId, array $card): void
    {
        $rows = [];
        foreach ($card['keyboard'] as $row) {
            $buttons = [];
            foreach ($row as $button) {
                $buttons[] = new InlineKeyboardButtonTypeDTO(text: $button->text, callbackData: $button->callbackData);
            }
            $rows[] = $buttons;
        }

        $this->sender->send($botConfig, new SendMessageMethodDTO(
            chatId: $chatId,
            text: $card['text'],
            parseMode: \BAGArt\TelegramBot\TgApi\Methods\Enum\ParseModeEnum::HTML,
            replyMarkup: $rows === [] ? null : new InlineKeyboardMarkupTypeDTO(inlineKeyboard: $rows),
        ));
    }

    private function answer(TgBotConfig $botConfig, CallbackQueryTypeDTO $dto, ?string $text = null): void
    {
        $this->sender->send($botConfig, new AnswerCallbackQueryMethodDTO(
            callbackQueryId: $dto->id,
            text: $text,
        ));
    }
}
