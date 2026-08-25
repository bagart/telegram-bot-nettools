<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands\Concerns;

use BAGArt\TelegramBotNettools\Contracts\Exceptions\FeatureDisabledException;
use BAGArt\TelegramBotNettools\NettoolsServices;

/**
 * Shared plumbing for probe commands: feature-group gating, /r bookkeeping
 * and probe telemetry (RFC §11 steps 1.6/1.11).
 *
 * @phpstan-require-property NettoolsServices $services
 */
trait RunsProbeCommand
{
    private function guardFeature(bool $enabled): void
    {
        if (! $enabled) {
            throw new FeatureDisabledException();
        }
    }

    private function rememberLast(int|string $chatId, string $args): void
    {
        $this->services->lastAction()->record($chatId, static::NAME, $args);
    }

    /** @param list<string> $degradedSources */
    private function telemetry(string $probe, bool $ok, int $latencyMs, int|string $chatId, array $degradedSources = [], ?string $target = null): void
    {
        $logger = null;
        if (isset($this->context) && $this->context instanceof \BAGArt\TelegramBot\Processing\BotProcessorContext) {
            $logger = $this->context->logger;
        }

        $this->services->metrics($logger)->record($probe, $ok, $latencyMs, $chatId, $degradedSources, $target);
    }
}
