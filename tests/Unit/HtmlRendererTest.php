<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Formatting\Footer;
use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;
use PHPUnit\Framework\TestCase;

/**
 * Formatting invariants (RFC §3.3): ≤3800 chars/message, overflow →
 * pagination, never truncation; footer at the end.
 */
final class HtmlRendererTest extends TestCase
{
    private HtmlRenderer $renderer;

    protected function setUp(): void
    {
        $this->renderer = new HtmlRenderer();
    }

    public function test_small_content_is_single_page(): void
    {
        $pages = $this->renderer->renderPages(
            'WHOIS · example.org',
            [new Section('Summary', ['Registrar: RegistrarOps'])],
            (new Footer())->add('rdap', 800),
        );

        self::assertCount(1, $pages);
        self::assertStringContainsString('<b>WHOIS · example.org</b>', $pages[0]);
        self::assertStringContainsString('Registrar: RegistrarOps', $pages[0]);
        self::assertStringContainsString('Sources (1): rdap', $pages[0]);
        self::assertStringEndsWith('live</i>', $pages[0]);
    }

    public function test_every_page_within_budget(): void
    {
        $lines = [];
        for ($i = 0; $i < 400; $i++) {
            $lines[] = 'record '.$i.': '.str_repeat('x', 40).' <b>'.($i * 7).'</b>';
        }

        $pages = $this->renderer->renderPages('DNS MATRIX', [
            new Section('Records', $lines, monospace: true),
            new Section('Extra', array_fill(0, 100, 'padding line '.str_repeat('y', 60))),
        ]);

        self::assertGreaterThan(1, count($pages));
        foreach ($pages as $page) {
            self::assertLessThanOrEqual(HtmlRenderer::MAX_CHARS, mb_strlen($page));
        }
    }

    public function test_no_line_lost_across_pages(): void
    {
        $lines = [];
        for ($i = 0; $i < 250; $i++) {
            $lines[] = 'MARKER_'.$i.'_'.str_repeat('z', 30);
        }

        $pages = $this->renderer->renderPages('BIG', [new Section('Rows', $lines)]);

        $joined = implode("\n", $pages);
        foreach ($lines as $line) {
            self::assertStringContainsString($line, $joined);
        }
    }

    public function test_monospace_wrapped_in_pre(): void
    {
        $page = $this->renderer->render('T', [new Section('Table', ['a  b', 'c  d'], monospace: true)]);

        self::assertStringContainsString('<pre>a  b', $page);
        self::assertStringContainsString('c  d</pre>', $page);
    }

    public function test_escapes_dynamic_values(): void
    {
        self::assertSame(
            'a &lt;b&gt; &amp;amp;&#039;&quot;',
            HtmlRenderer::esc('a <b> &amp;\'"'),
        );
    }

    public function test_footer_cached_age_humanized(): void
    {
        $footer = (new Footer())
            ->add('crt.sh', 2400, 2460)
            ->add('certspotter', 300);

        $rendered = $footer->render();

        self::assertStringContainsString('crt.sh · 2.4s · cached 41m', $rendered);
        self::assertStringContainsString('certspotter · 300 ms · live', $rendered);
        // 2 separators per source + 1 between sources
        self::assertSame(5, substr_count($rendered, '·'));
    }

    public function test_empty_sections_still_render_title(): void
    {
        $pages = $this->renderer->renderPages('EMPTY CARD', []);

        self::assertCount(1, $pages);
        self::assertSame('<b>EMPTY CARD</b>', trim($pages[0]));
    }
}
