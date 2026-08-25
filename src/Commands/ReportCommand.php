<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Configs\TgBotConfig;
use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBot\TgApi\Types\DTO\MessageTypeDTO;
use BAGArt\TelegramBotNettools\Formatting\Messages;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Support\RecoEngine;
use BAGArt\TelegramBotNettools\Support\ReportContextBuilder;
use BAGArt\TelegramBotNettools\Ui\Button;
use BAGArt\TelegramBotNettools\Ui\CallbackGrammar;
use BAGArt\TelegramBotNettools\Ui\ErrorCard;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;
use BAGArt\TelegramBotNettools\Ui\ReportCard;
use Throwable;

/**
 * /report <domain> (RFC §4.4): aggregated mega-report — cache-first section
 * assembly, score headline, top issues, degraded/failed transparency.
 * Heavy op → confirmation card first (§3.8). Weight 8.
 */
#[TgCommandAttribute(name: 'report')]
final class ReportCommand extends ProbeCommand
{
    public const string NAME = 'report';

    public const int WEIGHT = 8;

    /** Worst-case wall for the whole section sweep (semaphore TTL basis). */
    public const int HEAVY_CAP_SECONDS = 60;

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->auditEnabled;
    }

    protected function beforeRun(NetTarget $target, bool $confirmed, string $chatId): ?array
    {
        if ($confirmed || ! $this->effSettings->heavyConfirm) {
            return null;
        }

        $ref = $this->services->targetRef()->remember($target->host, self::NAME);
        $this->services->formState()->set($chatId, null, [
            'flow' => 'confirm',
            'step' => 'run',
            'draft' => ['command' => self::NAME, 'ref' => $ref, 'host' => $target->host],
        ]);

        return \BAGArt\TelegramBotNettools\Ui\ConfirmCard::render(self::NAME, (int) $chatId, self::WEIGHT, $target->host, $ref);
    }

    public function execute(
        TgBotConfig $botConfig,
        string $chatId,
        int|string|null $userId,
        string $argsRaw,
        bool $confirmed = false,
        ?MessageTypeDTO $dto = null,
    ): void {
        $input = $this->parseArgs($argsRaw);

        if ($input === '') {
            $this->sendCard($botConfig, $chatId, [
                'text' => Messages::format('usage_target', ['command' => self::NAME]),
                'keyboard' => [],
            ]);

            return;
        }

        try {
            if (! $this->featureEnabled($this->services->settings)) {
                throw new \BAGArt\TelegramBotNettools\Contracts\Exceptions\FeatureDisabledException();
            }

            $netTarget = $this->services->targets->inspect($input);

            if ($gateCard = $this->beforeRun($netTarget, $confirmed, $chatId)) {
                $this->sendCard($botConfig, $chatId, $gateCard);

                return;
            }

            // Heavy slot first: a busy rejection must never consume quota
            try {
                $this->services->semaphore->acquire(self::HEAVY_CAP_SECONDS);
            } catch (\BAGArt\TelegramBotNettools\Contracts\Exceptions\SemaphoreBusyException $exception) {
                $this->services->metrics($this->context->logger)->recordEvent('semaphore_busy');

                throw $exception;
            }
            $this->services->metrics($this->context->logger)->recordEvent('heavy_acquired');

            $startedAt = microtime(true);
            $this->services->quota->charge($chatId, $userId, self::WEIGHT);

            // ack → collect (sections stream through the shared probe cache)
            $context = (new ReportContextBuilder($this->services))->build($netTarget);
            $totalMs = (int) round((microtime(true) - $startedAt) * 1000);

            $verdict = count($context['results']) >= 2
                ? (new RecoEngine())->evaluate($context['results'])
                : null;

            $card = ReportCard::render(
                $netTarget->host,
                $totalMs,
                $context['results'],
                $context['degraded'],
                $context['failed'],
                $verdict,
            );

            $nav = [];
            foreach (array_keys($context['results']) as $section) {
                if (in_array($section, ['dns', 'whois', 'ssl', 'sec', 'mail', 'http'], true)) {
                    $nav[] = new Button(strtoupper($section), CallbackGrammar::encode(
                        'go',
                        (int) $chatId,
                        $this->services->targetRef()->remember($netTarget->host, $section)
                    ));
                    if (count($nav) === 3) {
                        $card['keyboard'][] = $nav;
                        $nav = [];
                    }
                }
            }
            if ($nav !== []) {
                $card['keyboard'][] = $nav;
            }
            $card['keyboard'][] = MenuBackRow::row((int) $chatId);

            $this->services->lastAction()->record($chatId, self::NAME, $input);
        } catch (Throwable $exception) {
            $card = ErrorCard::fromException($exception, (int) $chatId);
        } finally {
            $this->services->semaphore->release();
        }

        $this->sendCard($botConfig, $chatId, $card);
    }

    protected function parseArgs(string $argsRaw): string
    {
        return trim($argsRaw);
    }
}
