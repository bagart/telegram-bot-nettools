<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;
use BAGArt\TelegramBotNettools\Formatting\Section;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MainMenuKb;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;

/**
 * Pure /nt screens: text + keyboard rows. No SDK calls, no I/O —
 * snapshot-tested output.
 */
final class NtCards
{
    /**
     * @param  list<string>  $capabilityLines  e.g. ["ping: ✅", "trace: traceroute ✅"]
     * @return array{text: string, keyboard: list<list<Button>>}
     */
    public static function mainMenu(int $chatId, string $version, array $capabilityLines): array
    {
        $lines = [
            '<b>NETTOOLS · v'.HtmlRenderer::esc($version).'</b>',
            'Auditor toolkit for domains, IPs and TLS.',
            '',
            '<b>Capabilities</b>',
            ...array_map(static fn (string $line): string => HtmlRenderer::esc($line), $capabilityLines),
            '',
            '<i>Passive public data only. Scan your own hosts; local laws apply.</i>',
        ];

        return [
            'text' => implode("\n", $lines),
            'keyboard' => MainMenuKb::rows($chatId),
        ];
    }

    /**
     * Per-chat settings screen (RFC §3.5). Toggles write through the router.
     *
     * @param  array{detail_mode:string, heavy_confirm:?bool, auto_capture:?bool}  $state
     * @return array{text: string, keyboard: list<list<Button>>}
     */
    public static function settings(int $chatId, array $state): array
    {
        $mark = static fn (?bool $value, bool $default): string => ($value ?? $default) ? 'on' : 'off';

        return [
            'text' => (new HtmlRenderer())->render('SETTINGS', [
                new Section('', [
                    'Heavy-op confirmation: <b>'.$mark($state['heavy_confirm'], true).'</b>',
                    'Target auto-save: <b>'.$mark($state['auto_capture'], true).'</b>',
                    '',
                    '<i>Settings are per chat.</i>',
                ]),
            ], null),
            'keyboard' => [
                [
                    new Button('Heavy confirm', CallbackGrammar::encode('set_heavy', $chatId)),
                    new Button('Auto-save', CallbackGrammar::encode('set_autosave', $chatId)),
                ],
                [new Button('« Menu', CallbackGrammar::encode('menu', $chatId))],
            ],
        ];
    }

    /**
     * Tools grid (RFC §3.5): grouped by purpose; tapping asks for a target
     * (two-step form, §3.6) via the router 'ask' action.
     */
    public static function tools(int $chatId): array
    {
        $tool = static fn (string $label, string $command): Button => new Button(
            $label,
            CallbackGrammar::encode('ask', $chatId, 'h'.substr(hash('sha256', 'ask|'.$command), 0, 10)),
        );

        return [
            'text' => (new HtmlRenderer())->render('TOOLS', [
                new Section('', [
                    '<b>RECON</b>  ip · whois · dns · asn · http · subs',
                    '<b>NETWORK</b>  ping · trace · port · os',
                    '<b>AUDIT</b>  ssl · sec · mail · reco · report',
                    '',
                    '<i>Pick a tool — then send a domain or IP.</i>',
                ]),
            ], null),
            'keyboard' => [
                [$tool('IP', 'ip'), $tool('WHOIS', 'whois'), $tool('DNS', 'dns')],
                [$tool('ASN', 'asn'), $tool('HTTP', 'http'), $tool('SUBS', 'subs')],
                [$tool('PING', 'ping'), $tool('TRACE', 'trace'), $tool('PORT', 'port')],
                [$tool('SSL', 'ssl'), $tool('SEC', 'sec'), $tool('MAIL', 'mail')],
                [$tool('OS', 'os'), $tool('RECO', 'reco'), $tool('REPORT', 'report')],
                [new Button('« Menu', CallbackGrammar::encode('menu', $chatId))],
            ],
        ];
    }

    /**
     * @return array{text: string, keyboard: list<list<Button>>}
     */
    public static function help(int $chatId): array
    {
        $lines = ['<b>NETTOOLS · COMMANDS</b>', '', '<b>Available now</b>'];

        foreach (CommandCatalog::shipped() as $entry) {
            $lines[] = self::formatEntry($entry);
        }

        $lines[] = '';
        $lines[] = '<b>Roadmap</b>';
        foreach (CommandCatalog::all() as $entry) {
            if (! $entry->shipped) {
                $lines[] = self::formatEntry($entry, '🚧 ');
            }
        }

        $lines[] = '';
        $lines[] = '<i>&lt;target&gt;</i> = domain, IPv4/IPv6 or URL.';
        $lines[] = '<i>Weights are quota units/day/user.</i>';

        return [
            'text' => implode("\n", $lines),
            'keyboard' => [MenuBackRow::row($chatId)],
        ];
    }

    private static function formatEntry(CommandCatalogEntry $entry, string $prefix = ''): string
    {
        return sprintf(
            '%s/%s — %s <i>(%d)</i>',
            $prefix,
            HtmlRenderer::esc($entry->name),
            HtmlRenderer::esc($entry->description),
            $entry->weight,
        );
    }
    /**
     * /nt doctor source-health table (§3.2). Pure renderer; the command
     * gathers capability + breaker rows.
     *
     * @param  list<string>  $capabilityLines
     * @param  list<string>  $sourceLines
     */
    public static function doctor(array $capabilityLines, array $sourceLines): string
    {
        return (new HtmlRenderer())->render('NETTOOLS DOCTOR', [
            new Section('Capabilities', array_map(static fn (string $l): string => HtmlRenderer::esc($l), $capabilityLines)),
            new Section('Sources', array_map(static fn (string $l): string => HtmlRenderer::esc($l), $sourceLines)),
        ], null);
    }

}
