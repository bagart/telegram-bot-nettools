<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Formatting;

/**
 * Card footer: "Sources: {source} · {latency} · live|cached {age}" —
 * doubles as user-visible tracing (formatting invariant: every card ends
 * with a Sources footer).
 */
final class Footer
{
    /** @var list<array{name: string, latencyMs: int, cachedAgeSeconds: ?int}> */
    private array $sources = [];

    public function add(string $sourceName, int $latencyMs, ?int $cachedAgeSeconds = null): self
    {
        $this->sources[] = ['name' => $sourceName, 'latencyMs' => $latencyMs, 'cachedAgeSeconds' => $cachedAgeSeconds];

        return $this;
    }

    public function isEmpty(): bool
    {
        return $this->sources === [];
    }

    public function render(): string
    {
        if ($this->sources === []) {
            return '';
        }

        $parts = [];
        foreach ($this->sources as $source) {
            $parts[] = $this->renderSource($source);
        }
        $count = count($parts);

        return 'Sources ('.$count.'): '.implode(' · ', $parts);
    }

    /** @param array{name: string, latencyMs: int, cachedAgeSeconds: ?int} $source */
    private function renderSource(array $source): string
    {
        $line = HtmlRenderer::esc($source['name']).' · '.$this->humanizeLatency($source['latencyMs']);

        if ($source['cachedAgeSeconds'] !== null) {
            $line .= ' · cached '.$this->humanizeAge($source['cachedAgeSeconds']);
        } else {
            $line .= ' · live';
        }

        return $line;
    }

    private function humanizeLatency(int $latencyMs): string
    {
        if ($latencyMs < 1000) {
            return "{$latencyMs} ms";
        }

        return round($latencyMs / 1000, 1).'s';
    }

    public static function humanizeAge(int $seconds): string
    {
        if ($seconds < 60) {
            return "{$seconds}s";
        }
        if ($seconds < 3600) {
            return intdiv($seconds, 60).'m';
        }

        return round($seconds / 3600, 1).'h';
    }
}
