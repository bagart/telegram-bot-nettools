<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Support;

use BAGArt\TelegramBotNettools\Sources\Port43TransportContract;

/**
 * Scripted port-43 transport: one answer per ask() call, in order.
 */
final class FakePort43Transport implements Port43TransportContract
{
    /** @var list<array{0: string, 1: string}> recorded [server, query] pairs */
    public array $asked = [];

    /** @var list<string|null> */
    private array $answers = [];

    public function __construct(?string ...$answers)
    {
        $this->answers = array_values($answers);
    }

    public function ask(string $server, string $query, int $timeoutSeconds): ?string
    {
        $this->asked[] = [$server, $query];

        return array_shift($this->answers);
    }
}
