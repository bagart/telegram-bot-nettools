<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Formatting;

/**
 * Splits sections into pages within a char budget. Overflow is paginated,
 * never truncated (formatting invariant).
 */
final class Paginator
{
    /**
     * @param  list<Section>  $sections
     * @return list<list<Section>>
     */
    public function paginate(array $sections, int $charBudget, string $title = '', string $footer = ''): array
    {
        if ($sections === []) {
            return [];
        }

        $fixedOverhead = mb_strlen($title) + mb_strlen($footer) + 16;

        $pages = [];
        $current = [];
        $currentSize = $fixedOverhead;

        foreach ($sections as $section) {
            $size = $section->charBudget();

            // Oversized single section: hard-split by lines across pages
            if ($fixedOverhead + $size > $charBudget) {
                if ($current !== []) {
                    $pages[] = $current;
                    $current = [];
                    $currentSize = $fixedOverhead;
                }

                foreach ($this->splitSection($section, $charBudget - $fixedOverhead - $this->continuationOverhead($section)) as $chunk) {
                    $pages[] = [$chunk];
                }

                continue;
            }

            if ($current !== [] && $currentSize + $size > $charBudget) {
                $pages[] = $current;
                $current = [];
                $currentSize = $fixedOverhead;
            }

            $current[] = $section;
            $currentSize += $size;
        }

        if ($current !== []) {
            $pages[] = $current;
        }

        return $pages;
    }

    /**
     * @return list<Section>
     */
    private function splitSection(Section $section, int $budget): array
    {
        $chunks = [];
        $lines = [];
        $size = $this->continuationOverhead($section);

        foreach ($section->lines as $line) {
            $lineSize = mb_strlen($line) + 1;

            if ($lines !== [] && $size + $lineSize > $budget) {
                $chunks[] = new Section($section->title, $lines, $section->monospace);
                $lines = [];
                $size = $this->continuationOverhead($section);
            }

            $lines[] = $line;
            $size += $lineSize;
        }

        if ($lines !== []) {
            $chunks[] = new Section($section->title, $lines, $section->monospace);
        }

        return $chunks === [] ? [new Section($section->title, [], $section->monospace)] : $chunks;
    }

    /** Header/space reserved on continuation pages of a split section. */
    private function continuationOverhead(Section $section): int
    {
        return mb_strlen($section->title) + 12 + ($section->monospace ? 11 : 0);
    }
}
