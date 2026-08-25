# bagart/telegram-bot-nettools

Nettools module for the [Telegram bot platform](../../../README.md): an
auditor / admin toolkit — whois/RDAP, DNS, geo/ASN, ping/traceroute,
TLS/mail/security-header audits, aggregated `/report` and a deterministic
recommendation engine `/reco`.


## Status — Phase 0 (skeleton + safety rails)

Shipped:

- `NettoolsModule` (disabled by default, fail-closed), first production
  consumer of the attributed-command framework (`#[TgCommandAttribute]` +
  `registerAttributed()`).
- Contracts: `NettoolsProbeContract`, `SourceContract`, error taxonomy
  (`Contracts/Exceptions/*` → i18n catalog messages).
- Results DTOs: `NetTarget`, `GuardVerdict`, `ProbeOptions`, `ProbeResult`
  (JSON round-trip safe), `SourcePayload`.
- Safety rails: `TargetNormalizer` (+IDN/URL/IPv6), `SsrfGuard` (RFC §5.2
  matrix incl. IPv4-mapped-IPv6 normalization), `TargetPipeline` (single
  resolution invariant), `QuotaLedger` (atomic user+chat budgets),
  `ProbeSemaphore` (heavy-probe serialization), `ProbeCache` (stampede-safe,
  negative caching), `CapabilityDetector` (warm()-time binary detection).
- Formatting kernel: `Section` / `Paginator` / `HtmlRenderer` (≤3800-char
  budget, pagination instead of truncation) / `Footer`.
- Commands: `/nt` (menu hub + help catalog), `/quota`; inline callback
  router for the `nt:v1:*` grammar (64-byte budget enforced).

## Command surface (MVP complete)

RECON: `/ip` (`/geo`) · `/whois` · `/dns` (+ propagation/diagnostics actions)
· `/asn` · `/http` · `/subs`
NETWORK: `/ping` (+ world ping) · `/trace` · `/port` · `/os`
AUDIT: `/ssl` · `/sec` (+ CORS/methods flags) · `/mail` (+ live SMTP check)
· `/reco` · `/report`
UI: `/nt` menu hub with tools grid, settings and `/nt doctor`; `/my` target
memory with habit-ranked context menus; `/r` repeat-last; heavy-op
confirmations; per-chat quotas; group etiquette.

Admin-gated: `/portscan`, `/dnsbl` (config feature flag + admin chats).
MCP tool: `NettoolsProbeTool` for AI agents (same guard/quota path).

## Ops notes

- **Binaries**: `apt-get install -y traceroute iputils-ping` in the deploy
  image, or accept degraded `/ping`/`/trace` (TCP-timing fallback is picked
  automatically; `warm()` detects at boot — see `/nt doctor`).
- **mmdb**: point `tg-nettools.mmdb.city/asn` at GeoLite2 files; refresh
  weekly via cron. Missing files → HTTP fallback chain (ip-api → RIPEstat)
  with visible degraded-source warnings.
- **Rate limits**: per-source circuit breaker opens after 3 consecutive
  failures for 10 min (`tg-nettools:brk:*` cache keys); `/nt doctor` renders
  live states. ip-api free tier is HTTP-only and capped at 45 req/min.
- **Blocking model**: process probes are argv-safe `proc_open` under hard
  caps (ping ≤4s, trace ≤15s, portscan ≤10s wall); heavy commands
  (/trace, /report, /portscan, world ping) hold the global semaphore key
  `tg-nettools:heavy` (one heavy probe per deployment; busy callers get a
  retry-in-~Ns card and are not quota-charged). Revisit triggers: >5 heavy
  probes/min sustained or >1 worker per bot.
- **Benchmark**: `php misc/BAGArt/telegram-bot-nettools/tools/bench.php`
  prints per-probe latency over fixture targets (no egress).

## Enable

Wiring (dev mode): path repository + PSR-4 mapping in the host `composer.json`,
provider `BAGArt\TelegramBotNettools\TelegramBotNettoolsServiceProvider` listed
in `bootstrap/providers.php`. Prod mode: `cmd/deps/install --mode=prod`.

```bash
php artisan tg:module:enable nettools --bot={bot_id}
```

Config is published from `config/tg-nettools.php` (merge; secrets via env:
`NETTOOLS_ADMIN_CHAT_IDS`, `NETTOOLS_MMDB_*`, …).

## Tests

```bash
cd misc/BAGArt/telegram-bot-nettools && composer test
```

## Acceptable use

Passive public data only. Scan your own hosts. Local laws apply.
