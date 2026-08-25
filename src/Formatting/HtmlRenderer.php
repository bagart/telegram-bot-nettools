<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Formatting;

/**
 * Telegram HTML card renderer. Formatting invariants (RFC §3.3):
 * ≤3800 chars per message; <pre> for tabular data; overflow → pagination,
 * never truncation.
 *
 * Lines are trusted markup — escape dynamic values with esc().
 */
final class HtmlRenderer
{
    public const int MAX_CHARS = 3800;

    public function __construct(
        private readonly Paginator $paginator = new Paginator(),
    ) {
    }

    /**
     * @param  list<Section>  $sections
     * @return list<string> message texts, each within MAX_CHARS
     */
    public function renderPages(string $title, array $sections, ?Footer $footer = null): array
    {
        $footerText = $footer?->render() ?? '';

        $pages = $this->paginator->paginate($sections, self::MAX_CHARS, $title, $footerText);
        if ($pages === []) {
            return [$this->assemble($title, [], $footerText)];
        }

        $rendered = [];
        foreach ($pages as $pageSections) {
            $rendered[] = $this->assemble($title, $pageSections, $footerText);
        }

        return $rendered;
    }

    /**
     * Single-page convenience: first page only (caller guarantees budget).
     *
     * @param  list<Section>  $sections
     */
    public function render(string $title, array $sections, ?Footer $footer = null): string
    {
        return $this->renderPages($title, $sections, $footer)[0];
    }

    public static function esc(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * @param  list<Section>  $sections
     */
    private function assemble(string $title, array $sections, string $footerText): string
    {
        $parts = ['<b>'.self::esc($title).'</b>'];

        foreach ($sections as $section) {
            $body = implode("\n", $section->lines);

            if ($section->monospace) {
                $body = "<pre>{$body}</pre>";
            }

            $header = $section->title !== '' ? "\n<b>".self::esc($section->title)."</b>\n" : '';
            $parts[] = $header.$body;
        }

        if ($footerText !== '') {
            $parts[] = "\n<i>".$footerText.'</i>';
        }

        return trim(implode("\n", $parts));
    }
}
