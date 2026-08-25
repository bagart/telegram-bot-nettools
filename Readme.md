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
· `/asn` · `/http` · `/subs` (takeover hints fetch-verified against provider not-found pages)
NETWORK: `/ping` (+ world ping, progressive draft previews) · `/trace` (hops stream live via `sendMessageDraft`, final card persists) · `/port` · `/os`
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
- **Highload checklist (Phase 4.1 self-review)**:
  | Probe | Timeout | Semaphore | Cache TTL | Flush-on-shutdown |
  |---|---|---|---|---|
  | ping | 4s wall | heavy slot | never (measurement) | n/a (proc closed per call) |
  | trace | 15s wall | heavy slot | never | n/a |
  | portscan | 10s wall, ≤32 sockets | admin-only | never | sockets closed per probe |
  | http/sec/ssl | 3–5s each hop | — | 1h | transport-managed |
  | whois/dns/asn/ip/mail/subs | 2–8s per source | single-flight cache lock | 30min–24h | cache adapter |
  All egress goes through SSRF-guarded pins (`CURLOPT_RESOLVE`) with the
  single-resolution invariant; breaker keys and quota ledger are plain cache
  counters (safe to lose on flush).
- **Rollout / go-live checklist (§16)** — the module ships code-complete;
  enabling it for users is an ops action on the target host:
  1. `composer dump-autoload` (or `cmd/deps/install` in prod mode) and run
     migrations (`tg_nettools_targets`).
  2. Install binaries: `apt-get install -y traceroute iputils-ping`
     (degraded fallbacks are automatic but weaker).
  3. Configure `config/tg-nettools.php` (resolvers, quotas, heavy flags,
     admin-gated `portscanEnabled`/`dnsblEnabled` stay OFF until reviewed).
  4. Register the provider in `bootstrap/providers.php`, enable the module
     for the bot, set the webhook.
  5. Run the smoke gate on that host:
     `php misc/BAGArt/telegram-bot-nettools/tools/probe-smoke.php --heavy`
     — exit 0 required; the printed table is the §15 latency evidence.
  6. In-chat smoke: `/nt` → doctor shows all sources closed; run one command
     per family (/ip /ssl /mail /subs); check `/quota`.
  Rollback = disable module enablement flag (no schema rollback needed).

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
