<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Ui;

/**
 * Command catalog: weights (quota cost, RFC §3.1) and shipped/planned state.
 * Drives /nt help and the future tools grid.
 */
final readonly class CommandCatalogEntry
{
    public function __construct(
        public string $name,
        public string $description,
        public int $weight,
        public bool $shipped,
    ) {
    }
}
