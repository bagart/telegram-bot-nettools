<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Configs\TgBotConfig;
use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBot\TgApi\Types\DTO\MessageTypeDTO;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Support\RecoEngine;
use BAGArt\TelegramBotNettools\Support\ReportContextBuilder;
use BAGArt\TelegramBotNettools\Ui\Button;
use BAGArt\TelegramBotNettools\Ui\CallbackGrammar;
use BAGArt\TelegramBotNettools\Ui\RecoCard;

/**
 * /reco <domain> (RFC §8): deterministic recommendations scorecard over a
 * ReportContext. Charges once (weight 2) — sections ride the probe cache.
 */
#[TgCommandAttribute(name: 'reco')]
final class RecoCommand extends ProbeCommand
{
    public const string NAME = 'reco';

    public const int WEIGHT = 2;

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->auditEnabled;
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
                'text' => \BAGArt\TelegramBotNettools\Formatting\Messages::format('usage_target', ['command' => self::NAME]),
                'keyboard' => [],
            ]);

            return;
        }

        try {
            if (! $this->featureEnabled($this->services->settings)) {
                throw new \BAGArt\TelegramBotNettools\Contracts\Exceptions\FeatureDisabledException();
            }

            $netTarget = $this->services->targets->inspect($input);
            $this->services->quota->charge($chatId, $userId, self::WEIGHT);

            $context = (new ReportContextBuilder($this->services))->build($netTarget);
            $verdict = (new RecoEngine())->evaluate($context['results']);

            foreach ($context['degraded'] as $entry) {
                $verdict['findings'][] = [
                    'severity' => 'info',
                    'id' => 'degraded_source',
                    'detail' => '[report] section source unavailable: '.$entry,
                    'hint' => 're-run later for full coverage',
                ];
            }
            usort($verdict['findings'], static fn (array $a, array $b): int => [(string) $a['severity'], (string) $a['id']]
                <=> [(string) $b['severity'], (string) $b['id']]);

            $card = RecoCard::render($verdict, $netTarget->host);
            $reportRef = $this->services->targetRef()->remember($netTarget->host, ReportCommand::NAME);
            $card['keyboard'] = [[
                new Button('📊 Full report', CallbackGrammar::encode('go', (int) $chatId, $reportRef)),
                ...\BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow::row((int) $chatId),
            ]];

            $this->services->lastAction()->record($chatId, self::NAME, $input);
        } catch (\Throwable $exception) {
            $card = \BAGArt\TelegramBotNettools\Ui\ErrorCard::fromException($exception, (int) $chatId);
        }

        $this->sendCard($botConfig, $chatId, $card);
    }

    protected function parseArgs(string $argsRaw): string
    {
        return trim($argsRaw);
    }
}
