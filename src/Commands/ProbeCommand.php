<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Configs\TgBotConfig;
use BAGArt\TelegramBot\Contracts\Outbound\TgSenderContract;
use BAGArt\TelegramBot\Contracts\Processing\Processors\TgModuleProcessorContract;
use BAGArt\TelegramBot\Contracts\TgApi\TgApiTypeDTOContract;
use BAGArt\TelegramBot\Modules\TgCommandRegistry;
use BAGArt\TelegramBot\Processing\BotProcessorContext;
use BAGArt\TelegramBot\Processing\ErrorHandling\ProcessorErrorContext;
use BAGArt\TelegramBot\TgApi\Types\DTO\MessageTypeDTO;
use BAGArt\TelegramBotNettools\Commands\Concerns\SendsCards;
use BAGArt\TelegramBotNettools\Formatting\Messages;
use BAGArt\TelegramBotNettools\NettoolsModule;
use BAGArt\TelegramBotNettools\NettoolsServices;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\Button;
use BAGArt\TelegramBotNettools\Ui\ErrorCard;

/**
 * Shared skeleton for every probe command (RFC §4.1 "thin orchestrators"):
 * normalize → guard (cost 0) → optional pre-run gate → quota → cache-or-probe
 * → card, plus /r bookkeeping, target-memory capture and telemetry.
 *
 * Subclasses declare NAME/WEIGHT and provide the probe factory + card
 * renderer; everything else — usage text, error card, degraded warnings,
 * repeat-last registration — is uniform.
 */
abstract class ProbeCommand implements TgModuleProcessorContract
{
    use SendsCards;

    public const string NAME = '';

    public const int WEIGHT = 1;

    public function __construct(
        protected readonly TgSenderContract $sender,
        protected readonly NettoolsServices $services,
        protected readonly BotProcessorContext $context,
    ) {
    }

    public static function moduleId(): string
    {
        return NettoolsModule::ID;
    }

    public static function build(BotProcessorContext $context): static
    {
        return new static(
            sender: $context->tgSender,
            services: NettoolsServices::fromSetup($context->botSetup),
            context: $context,
        );
    }

    public function support(TgApiTypeDTOContract $dto, TgBotConfig $botConfig, ?string $action = null): bool
    {
        if (! $dto instanceof MessageTypeDTO || $dto->text === null) {
            return false;
        }

        $name = TgCommandRegistry::parseCommandName($dto->text);

        return $name !== null && ($name === static::NAME || in_array($name, static::aliases(), true));
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

        $args = mb_substr((string) $dto->text, strlen(static::NAME) + 1);
        $this->execute($botConfig, (string) $dto->chat->id, $dto->from?->id, $args, dto: $dto);
    }

    public function onException(ProcessorErrorContext $context): void
    {
    }

    /**
     * Full flow, also invoked by /r and callback confirmations.
     */
    protected int|string|null $callerUserId = null;

    /** Chat-overlay settings resolved at execute() start (RFC §3.5). */
    protected \BAGArt\TelegramBotNettools\NettoolsSettings $effSettings;

    public function execute(
        TgBotConfig $botConfig,
        string $chatId,
        int|string|null $userId,
        string $argsRaw,
        bool $confirmed = false,
        ?MessageTypeDTO $dto = null,
    ): void {
        $this->callerUserId = $userId;

        if ($dto !== null && ($card = $this->etiquetteGate($dto, $botConfig, $chatId)) !== null) {
            $this->sendCard($botConfig, $chatId, $card);

            return;
        }

        $this->effSettings = $this->services->chatSettings()->apply($chatId, $this->services->settings);
        $input = $this->parseArgs($argsRaw);

        if ($input === '') {
            $this->sendCard($botConfig, $chatId, [
                'text' => Messages::format($this->usageKey(), ['command' => static::NAME]),
                'keyboard' => [],
            ]);

            return;
        }

        $ok = false;
        $degraded = [];
        $latencyMs = 0;
        $probeName = static::NAME;

        try {
            if (! $this->featureEnabled($this->effSettings)) {
                throw new \BAGArt\TelegramBotNettools\Contracts\Exceptions\FeatureDisabledException();
            }

            // Normalize + guard cost 0 (§5.3); quota charges after that only
            $netTarget = $this->syntheticTarget($input)
                ?? $this->services->targets->inspect($input);

            if ($gateCard = $this->beforeRun($netTarget, $confirmed, $chatId)) {
                $this->sendCard($botConfig, $chatId, $gateCard);

                return;
            }

            $this->services->quota->charge($chatId, $userId, static::WEIGHT);

            [$probe, $options] = $this->probeFor($netTarget);
            $probeName = $probe->name();
            $startedAt = microtime(true);

            $result = $this->services->probeCache->getOrSet(
                $probe,
                $netTarget,
                $options,
                fn (): ProbeResult => $probe->probe($netTarget, $options),
            );
            $latencyMs = (int) round((microtime(true) - $startedAt) * 1000);

            $degraded = $result->degradedSources;
            $card = $this->renderCard($result, (int) $chatId, $netTarget->host);

            $this->services->lastAction()->record($chatId, static::NAME, $input);
            $this->services->memory()->recordUse($userId, $netTarget->host, static::NAME);
            $ok = true;
        } catch (\Throwable $exception) {
            if (getenv('NT_DEBUG') !== false) {
                throw $exception;
            }
            $card = ErrorCard::fromException($exception, (int) $chatId);
        }

        $this->services->metrics($this->context->logger)->record(
            $probeName,
            $ok,
            $latencyMs,
            $chatId,
            is_array($degraded) ? $degraded : [],
            $input !== '' ? $input : null,
        );

        if ($ok && $userId !== null) {
            $remaining = $this->services->quota->remaining($chatId, $userId);
            $card['text'] .= "\n\n<i>💰 {$remaining} units left today · /quota</i>";
        }

        $this->sendCard($botConfig, $chatId, $card);
    }

    /**
     * Group etiquette (RFC §3.9): in groups answer only on reply/@mention
     * (admin check needs the API — reply/mention covers the honest MVP set).
     * Silent ignore + one-time hint per chat.
     *
     * @return array{text: string, keyboard: list<list<Button>>}|null null = proceed
     */
    private function etiquetteGate(MessageTypeDTO $dto, TgBotConfig $botConfig, string $chatId): ?array
    {
        if (($dto->chat->type?->value ?? 'private') === 'private' || $dto->replyToMessage !== null) {
            return null;
        }

        if (str_contains(trim((string) ($dto->text ?? '')), '@')) {
            return null;
        }

        $hinted = $this->services->cache->get('tg-nettools:etq:'.$chatId) === 1;
        $this->services->cache->put('tg-nettools:etq:'.$chatId, 1, 3600);

        return $hinted ? null : [
            'text' => '<i>Tip: in groups reply to a message or @mention the bot to run nettools commands.</i>',
            'keyboard' => [],
        ];
    }

    /** Extra command names accepted by support() (e.g. /geo for /ip). */
    /** @return list<string> */
    protected static function aliases(): array
    {
        return [];
    }

    /**
     * Target argument after the command word; '' → usage card.
     */
    protected function parseArgs(string $argsRaw): string
    {
        return trim($argsRaw);
    }

    protected function usageKey(): string
    {
        return 'usage_target';
    }

    /** Feature-group kill-switch from settings; default: always on. */
    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return true;
    }

    /**
     * Pre-quota gate: heavy-confirm cards, rate limits. Return a card to send
     * INSTEAD of running (it must have charged nothing), or null to proceed.
     *
     * @return array{text: string, keyboard: list<list<Button>>}|null
     */
    protected function beforeRun(NetTarget $target, bool $confirmed, string $chatId): ?array
    {
        return null;
    }

    /**
     * Probe factory. Options carry flags + timeout for this probe only.
     * Multi-probe commands (/reco, /report) bypass these hooks entirely.
     *
     * @return array{0: \BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract, 1: ProbeOptions}
     */
    protected function probeFor(NetTarget $target): array
    {
        throw new \LogicException(static::NAME.' does not use the single-probe path');
    }

    /** @return array{text: string, keyboard: list<list<Button>>} */
    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        throw new \LogicException(static::NAME.' does not use the single-probe path');
    }

    /**
     * Hook for commands accepting non-host inputs (/asn AS-numbers): return a
     * synthetic NetTarget to skip the resolve pipeline entirely, or null.
     */
    protected function syntheticTarget(string $rawInput): ?NetTarget
    {
        unset($rawInput);

        return null;
    }

    /** @param list<string> $parts */
    protected static function firstToken(string $args): string
    {
        $parts = preg_split('/\s+/', trim($args)) ?: [];

        return trim($parts[0] ?? '');
    }
}
