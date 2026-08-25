<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Formatting;

/**
 * Card building block: titled group of text lines. Lines are trusted markup
 * — formatters must escape dynamic values via HtmlRenderer::esc().
 */
final readonly class Section
{
    /**
     * @param  list<string>  $lines
     */
    public function __construct(
        public string $title,
        public array $lines,
        public bool $monospace = false,
    ) {
    }

    /** Rendered length estimate used by the paginator (cheap, close enough). */
    public function charBudget(): int
    {
        $overhead = mb_strlen($this->title) + 8; // <b></b> + newlines

        foreach ($this->lines as $line) {
            $overhead += mb_strlen($line) + 1;
        }

        if ($this->monospace) {
            $overhead += 11; // <pre>\n</pre>
        }

        return $overhead;
    }
}
