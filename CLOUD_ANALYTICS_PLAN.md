# Cloud Analytics Integration — Design & Implementation Plan

Admitting `drumscore-cloud` as a second producer into this collector.

**Status:** proposed. **Date:** 2026-07-26 (revised 2026-07-27).

**The decisions live in the cloud repo's ADR log** (branch
`adr-0035-backend-analytics`), which is where this project's architecture
decisions are recorded — this repo has no ADR practice, and one wouldn't be
worth starting for a single record:

- **ADR-0036 — collector multi-producer contract.** The `source` dimension,
  allowlist split, view scoping, rollup. **Authoritative for everything in this
  repo.**
- **ADR-0035 — backend analytics.** The cloud side: emitter, audit tap, sink
  resolution, event taxonomy. Its emitter exists unwired on branch
  `analytics-emitter` (`internal/analytics/`, 645 lines, tests, no call sites).

This document is the **evidence and the sequencing**: what reading the code
turned up (§3), the exact schema and queries (§5–6), and the phased plan with
verification (§7–9). Where it and an ADR disagree about *why*, the ADR wins.

---

## 1. Summary

The ADR's shape is right: reuse this collector, one more producer, additive
`source` dimension, per-environment collectors, non-blocking emitter. This plan
keeps that shape and fills in what reading the two codebases side by side turned
up: **nine concrete blockers, of which four would silently lose or corrupt data
rather than fail loudly.** It then specifies the view strategy in detail, since
that is where "add a second producer" actually becomes visible.

Headline decisions:

- **`source` column, default `'dse-app'`** — additive, existing rows unchanged.
- **`cloud.*` names in a *separate* allowlist file**, not `features.json`
  (which is regenerated from the dse-mxml enum at each release and would wipe
  them).
- **Existing `/analytics` is scoped to `source = 'dse-app'`** — its numbers stay
  bit-identical to today.
- **A new `/cloud` view**, not a source toggle on `/analytics` — the metric
  vocabulary genuinely differs (see §5.2).
- **No new event type, no new `os_family`/`os_arch` values** — both are guarded
  by SQLite `CHECK` constraints, which cannot be widened without a table
  rebuild. This resolves ADR **OQ1** on evidence.

Work splits roughly 60/40 collector/cloud, and the collector half must ship
first.

---

## 2. What already exists

**Collector (this repo, `api/main.go`, 3062 lines, single file).**
`POST /api/analytics/batch` (`main.go:1493`) → HMAC check → `validateBatch`
(`main.go:870`) → one row per event into `analytics_events` (`main.go:1573`).
Dashboards: `/platforms` (version-check stats, reads `version_checks` only) and
`/analytics` (feature stats, six queries over `analytics_events`,
`main.go:1899`). A monthly job rolls `feature_used` into
`feature_monthly_aggregates` and prunes raw rows older than a year
(`main.go:1147`–`1237`).

**Emitter (cloud, branch `analytics-emitter`).** `Emitter` interface,
`httpEmitter` with bounded channel, periodic + threshold flush, `429` backoff
with re-enqueue, drop-on-full counter, `NopEmitter`, and `Resolve()` for
safe-by-default sink selection. It is well built and matches the wire contract —
it is simply not called from anywhere, and several of its defaults collide with
this collector's validation (§3).

**Tap point (cloud).** `audit.Writer` is an interface constructed in exactly one
place — `internal/server/router.go:59`, `auditWriter := audit.NewPgWriter()` —
and injected into every repository and handler. One decorator there covers score,
folder, tag, share, and lock mutations.

---

## 3. Findings — what breaks if the ADR is implemented as written

Ordered by severity. Each is verified against the code, not inferred.

### F1 — `source` is dropped on the floor (silent data mixing)
`AnalyticsBatch` (`main.go:71`) has no `Source` field. Go's `json.Unmarshal`
discards unknown keys, so the emitter's `"source":"cloud-backend"` is accepted
and ignored. Cloud events would land **indistinguishable from desktop events**
and immediately distort every `/analytics` figure, with no error anywhere.
*This is the one that must not ship late.*

### F2 — `sessionStart` anchored at boot expires after 7 days (total, permanent loss)
`validateBatch` rejects a batch whose `sessionStart` is older than 7 days
(`main.go:900`). `httpEmitter` stamps `sessionStart` **once, at construction**
and reuses it for the process lifetime. A cloud instance up for eight days has
**every batch 400'd forever**, and the emitter drops non-429 failures with only
a log line. A server has no session; the desktop assumption doesn't port.

### F3 — one unknown feature name rejects the *whole batch*
The allowlist check (`main.go:915`) returns an error for the batch, not the
event. Until `cloud.*` names are allow-listed, every cloud batch 400s; after,
any single unregistered new event name discards up to 500 good events with it.

### F4 — `features.json` is regenerated at release time
Per the release runbook, `features.json` is refreshed on snare from the dse-mxml
`AnalyticsFeature` enum. Putting `cloud.*` entries in that file means the next
release silently deletes them → back to F3. **Cloud names need their own file.**

### F5 — cloud rows would be stamped `edition = 'studio'`
`edition` is `NOT NULL DEFAULT 'studio'` (`main.go:810`) and `normalizeEdition`
(`main.go:856`) coerces anything unrecognised to `studio`. Cloud batches send no
edition, so every cloud row becomes a "studio" row — actively misleading for
edition / paid-vs-free analysis, which is already only valid on 3.6.4+ data.

### F6 — flush cadence exceeds the nginx rate limit
`analytics_limit` is `1r/m` keyed on `$http_x_client_id` (`nginx.conf:36`),
burst 10. All cloud events from one instance share one client id, so one bucket.
The emitter's default `FlushInterval` is 30s = **2r/m sustained**. The server
does set `limit_req_status 429` (`nginx.conf:179`), so the emitter's backoff
*does* engage and it degrades rather than breaks — but it will live in backoff,
and a 5000-event queue behind a 15-minute ceiling will drop. Cheap fix on the
emitter side; no nginx change needed.

### F7 — non-429 rejections are invisible
`send()` discards the response body (`io.Copy(io.Discard, resp.Body)`) and
returns `sendDrop` on any non-2xx/429. The collector's genuinely useful
`{"error":...,"details":"unknown feature name: cloud.x"}` is thrown away. F2/F3/F5
would all present as "analytics just isn't there" with no diagnostic.

### F8 — the yearly rollup would fuse cloud and app history permanently
`feature_monthly_aggregates` has no `source`, and the aggregation queries
(`main.go:1147`, `1174`, `1198`) group without it, then delete the raw rows
(`main.go:1231`). Once a month passes the one-year boundary, cloud and desktop
counts are merged into single rows with **no way back**. The `NOT IN`
idempotency guards keyed on `year_month || edition` also need `source` or they
will skip legitimate work.

### F9 — a new route is unreachable unless nginx is told
`nginx.conf` enumerates locations and ends with a deny-all `location /`
(`nginx.conf:378`), inside a server that already 444s non-Cloudflare,
non-local traffic (`nginx.conf:162`). A new `/cloud` page needs its own
`location` block or it is invisible in production.

**Also worth noting (not blockers):**
- `api/Dockerfile:10` copies **only `main.go`**. Any new `.go` file needs
  `COPY *.go .` — otherwise the build succeeds against stale code.
- Event timestamps get **no clock-skew tolerance** (`main.go:921`, `> now`)
  while `sessionStart` gets five minutes. A cloud clock a second fast 400s the
  batch. Worth aligning; it de-risks the desktop client too.
- `Resolve()`'s `DefaultNonProdCollector = "http://localhost:8080"` does not
  collide with the cloud backend's own `:8090` (`internal/config/config.go:108`),
  so the default is coherent — but only if a collector actually runs on the
  pre-prod box. Otherwise it is connection-refused spam every flush.
- The prod collector sits behind Cloudflare with authenticated origin pulls. A
  cloud instance POSTing to `https://support.drumscore.scot` traverses the edge
  and arrives as a Cloudflare IP with a valid cert, so `$allow_access` passes —
  but this should be **proved with curl from the cloud box** before it is
  assumed.

---

## 4. Design decisions

*Recorded in ADR-0036 (D1–D7, D9) and ADR-0035 §6–7 (D8). Restated here with the
engineering detail an implementer needs; the ADRs carry the rationale.*

**D1 — `source TEXT NOT NULL DEFAULT 'dse-app'` on `analytics_events`.**
Added by the existing `ALTER TABLE ... duplicate column` migration idiom
(`main.go:807`). Backfill is free: the default *is* the truth for every existing
row.

**D2 — `source` is a closed set, validated fail-closed.**
`validSources = {"dse-app", "cloud-backend"}`. An unrecognised source is a 400,
not a new namespace. An absent source defaults to `dse-app` (wire
back-compatibility with every shipped desktop client).

**D3 — cloud names live in `features-cloud.json`, loaded per source.**
Same `name → category` shape as `features.json`, new `CLOUD_FEATURES_FILE` env
(default `/app/features-cloud.json`), mounted read-only like its sibling. The
allowlist becomes `map[source]map[string]bool`. This keeps the release-time
regeneration of `features.json` from the Java enum idempotent and harmless (F4).

Note the asymmetry: **`features.json` is gitignored** (`.gitignore:14`) because
it is generated and scp'd to snare per release, whereas **`features-cloud.json`
is committed** — hand-authored, changing only with the cloud taxonomy. So it
ships with the repo and needs no release-time deployment step, unlike its
sibling.
Additionally enforce the namespace: `cloud-backend` events **must** be `cloud.*`,
`dse-app` events **must not** be. Cheap, and it keeps the two view populations
from ever leaking into each other.

**D4 — reuse `feature_used`; do not add an event type. (Resolves OQ1.)**
`analytics_events` has `CHECK(event_type IN ('feature_used','session_start',
'session_end','error'))` (`main.go:713`). SQLite cannot widen a `CHECK` via
`ALTER`; it needs a full table rebuild on a live production database. A `source`
column achieves the same separation for free. Cloud emits **only**
`feature_used` and `error` — no `session_start`/`session_end`, which would
corrupt the session metrics on `/analytics`.

**D5 — cloud rows keep `os_family='Linux'`, `os_arch='x86_64'`.**
Same `CHECK`-constraint reason (`main.go:714`). These fields are simply
meaningless for cloud rows; since all views are source-scoped (§5.1), nothing
reads them. Documented rather than modelled.

**D6 — cloud rows store `edition = 'n/a'`.**
`edition` carries no `CHECK` (it arrived via plain `ALTER`), so a distinct value
is storable. Fixes F5 explicitly rather than relying on view scoping, so a
future ad-hoc SQL query can't quietly count servers as Studio seats.

**D7 — account pseudonym in `metadata.account`, read via `json_extract`.**
Stable per-deployment salt (ADR **OQ2** default; longitudinal counts matter more
here than unlinkability, and the value never leaves our own box). A partial
expression index keeps the `/cloud` distinct-account query honest.

**D8 — the audit tap is a decorator on `audit.Writer` at `router.go:59`.**
One line at the single construction site covers every mutation path. Caveat to
accept explicitly: `EmitTx` runs *inside* the transaction, so a rolled-back
mutation still emits an analytics event. For best-effort product counts this
over-count is acceptable and rare; the alternative (tapping the committed
event-log tail poll) is strictly more accurate and strictly more machinery, and
can replace the decorator later without touching the collector.

**D9 — carry `source` through the rollup. (Resolves OQ3.)**
`feature_monthly_aggregates` gets `source` too, in the `GROUP BY` and in the
`NOT IN` idempotency keys (F8). Same retention, same job — separation preserved
into history, no second pipeline.

---

## 5. Views

The part with the most design freedom, and the part where getting it wrong is
least visible.

### 5.1 Existing `/analytics` becomes app-only

All seven statements in the `/analytics` handler get `AND source = 'dse-app'`:

| Query | Line |
|---|---|
| Feature popularity | `main.go:1957` |
| Total unique clients | `main.go:2001` |
| Time buckets | `main.go:2009` |
| Session count | `main.go:2045` |
| Session duration (both sides of the self-join) | `main.go:2060` |
| Version breakdown | `main.go:2074` |
| OS breakdown | `main.go:2109` |
| Country breakdown | `main.go:2144` |

Because every existing row defaults to `dse-app`, **the rendered page is
byte-identical before and after**. That property is the whole point: it makes
the change safe to deploy ahead of any cloud traffic, and it means the desktop
dashboard can never be distorted by a cloud misconfiguration.

`/platforms` needs **no change** — it reads `version_checks` exclusively
(verified across `main.go:1629`–`1897`), and the cloud backend never calls
`/api/version`.

### 5.2 New `/cloud` view — why separate, not a toggle

A `?source=` filter on `/analytics` is tempting and wrong. That template's
denominators are *unique desktop installs*: "Uses per Client", "Unique
Clients", per-OS and per-country splits. For the cloud backend, `client_id` is a
**server instance** — there will be one to three of them — so every per-client
rate collapses to a meaningless number, "unique clients" reads as `1`, and the
OS/country columns are constants (D5). Same table, different semantics; the
honest answer is a different page.

**Route** `/cloud` (+ `nginx.conf` location per F9), period selector identical to
the others (`hour|day|week|month|year`), nav bar gains a third tab.

**Sections:**

1. **Summary cards** — Total events · Distinct accounts active · Instances
   reporting · Errors.
2. **Event popularity** — `cloud.*` name, category (from
   `features-cloud.json`), total events, distinct accounts.
3. **Events over time** — same Chart.js + bucket-format switch as `/analytics`.
4. **Breakdowns** — three cards, all `json_extract` over `metadata`: share kind
   (`$.kind`), error class (`$.class`), and per-instance (`client_id`, truncated).

Representative queries:

```sql
-- distinct accounts active (the cloud analogue of "unique clients")
SELECT COUNT(DISTINCT json_extract(metadata, '$.account'))
FROM analytics_events
WHERE source = 'cloud-backend'
  AND timestamp >= datetime('now', '-7 days')
  AND json_extract(metadata, '$.account') IS NOT NULL;

-- event popularity
SELECT feature_name,
       COUNT(*)                                          AS total_events,
       COUNT(DISTINCT json_extract(metadata, '$.account')) AS accounts
FROM analytics_events
WHERE source = 'cloud-backend'
  AND event_type = 'feature_used'
  AND timestamp >= datetime('now', '-7 days')
GROUP BY feature_name
ORDER BY total_events DESC;
```

Supporting index:

```sql
CREATE INDEX IF NOT EXISTS idx_analytics_cloud_account
  ON analytics_events(json_extract(metadata, '$.account'))
  WHERE source = 'cloud-backend';
```

(`mattn/go-sqlite3` bundles JSON1; partial and expression indexes are both
supported.)

### 5.3 Shared period plumbing

The period → `(label, timeFilter, bucketFormat, granularity)` switch is already
duplicated between `/platforms` and `/analytics`; `/cloud` would make three.
Extract `resolvePeriod(period string) (periodSpec, error)` once and use it in
all three. This is the only refactor the plan asks for, and it is what stops the
third view from being a third copy.

### 5.4 Deliberately not built

No combined app+cloud overview page. Cross-producer comparison has no
well-defined denominator yet; when a real question needs it, it can be built on
the `source` column that this work puts in place.

---

## 6. Schema changes (complete)

Appended to the existing migration list at `main.go:807`, all
`duplicate column`-tolerant:

```sql
ALTER TABLE analytics_events           ADD COLUMN source TEXT NOT NULL DEFAULT 'dse-app';
ALTER TABLE feature_monthly_aggregates ADD COLUMN source TEXT NOT NULL DEFAULT 'dse-app';

CREATE INDEX IF NOT EXISTS idx_analytics_source     ON analytics_events(source);
CREATE INDEX IF NOT EXISTS idx_analytics_source_ts  ON analytics_events(source, timestamp);
CREATE INDEX IF NOT EXISTS idx_analytics_cloud_account
  ON analytics_events(json_extract(metadata, '$.account'))
  WHERE source = 'cloud-backend';
```

No table rebuild, no downtime, no backfill.

---

## 7. Implementation plan

### Phase A — collector accepts and separates (this repo, ships first)

Deployable and inert on its own: with no cloud traffic, behaviour is unchanged.

1. `source` on `AnalyticsBatch` (`main.go:71`); default to `dse-app` when empty.
2. `validSources` map; per-source allowlist `map[string]map[string]bool`;
   `loadFeatures` extended (or a sibling `loadCloudFeatures`) reading
   `CLOUD_FEATURES_FILE`; namespace check per D3.
3. `validateBatch` takes the resolved source; feature check consults the right
   allowlist; give event timestamps the same 5-minute skew tolerance as
   `sessionStart`.
4. Edition: `edition = 'n/a'` when source ≠ `dse-app` (D6).
5. Migrations + indexes (§6).
6. `INSERT` gains `source` (`main.go:1573`).
7. `features-cloud.json` committed with the §8 taxonomy; mounted in
   `docker-compose.yml` alongside `features.json`; `CLOUD_FEATURES_FILE` added
   to the `api` service env.
8. `api/Dockerfile:10` → `COPY *.go .` if the code is split at all.
9. **Fail-closed check:** confirm a batch with `source:"cloud-backend"` and an
   unregistered name still 400s, and that an absent `source` still stores
   `dse-app`.

### Phase B — views (this repo)

10. `resolvePeriod` extraction (§5.3).
11. `AND source = 'dse-app'` across the eight `/analytics` statements (§5.1).
12. `/cloud` handler + `api/templates/cloud.html` (clone the `/analytics`
    chrome, swap the metric vocabulary per §5.2).
13. Nav third tab in `analytics.html:297`, `platforms.html:297`, `cloud.html`.
14. `location /cloud` in `nginx.conf`, mirroring the `/analytics` block at
    `nginx.conf:274` (rate zone, security headers, no-cache) — F9.
15. Aggregation job: `source` in the three rollup `GROUP BY`s and in both
    `NOT IN` idempotency keys (`main.go:1147`, `1174`, `1198`) — F8.

### Phase C — emitter corrections (cloud, branch `analytics-emitter`)

16. **`sessionStart` stamped per flush, not per process** — F2. The single most
    important line in this phase.
17. `FlushInterval` default → **300s**, `BatchThreshold` → 500, matching the
    desktop client and living inside the 1r/m budget — F6.
18. On non-2xx, retain the first ~512 bytes of the response body in the log
    line; add a `rejected` counter beside `dropped` — F7.
19. `AppVersion` normalised to bare `major.minor.patch` (the collector's regex
    is strict; a `git describe` string 400s).
20. Emit `feature_used` and `error` only — no session events (D4).
21. Log connection-refused at a decaying rate, not once per flush.

### Phase D — cloud wiring

22. `ANALYTICS_*` fields in `internal/config` via the existing
    `envDefault`/`envBool` idiom; `analytics.Resolve` + `New` at boot; `Close`
    on shutdown alongside the existing graceful-shutdown path.
23. `auditEmitter` decorator wrapping `audit.Writer`, injected at
    `internal/server/router.go:59` (D8); maps the §8 subset of
    `(Operation, TargetType)` pairs, salted account hash into
    `metadata.account`, buckets only — never titles, bytes, or emails.
24. Direct emits for non-audited signals (viewer verify, sync subscribe).
25. `ACCOUNT_HASH_SALT` in config; treated as a secret, stable per deployment.

### Phase E — rollout

26. Deploy Phase A+B to snare (no cloud traffic yet) and confirm `/analytics`
    is unchanged and `/cloud` renders empty.
27. Stand up (or point at) a non-prod collector for the pre-prod box; verify the
    bare-launch default actually connects.
28. `curl` a signed cloud-shaped batch **from the cloud host** to
    `https://support.drumscore.scot/api/analytics/batch` — proves the
    Cloudflare/`$allow_access` path end to end.
29. Enable the emitter in pre-prod; watch `dropped`/`rejected` at zero for 24h.
30. Point prod at prod (both URL *and* secret, per ADR §5).

**Ordering constraint:** A before C/D. If the emitter ships first, F1 means
cloud events land as desktop events and the mixing is not retroactively
separable.

---

## 8. Event taxonomy (`features-cloud.json`)

ADR §"Starter event taxonomy", as the allowlist file this collector loads:

```json
{
  "cloud.score.created":   "Score",
  "cloud.score.updated":   "Score",
  "cloud.score.deleted":   "Score",
  "cloud.image.stored":    "Image",
  "cloud.share.minted":    "Share",
  "cloud.viewer.verified": "Share",
  "cloud.sync.subscribed": "Sync",
  "cloud.error":           "Error"
}
```

Metadata is buckets and enums only: `account` (salted hash), `kind`
(`view-snapshot|ds-copy|ds-access`), `size`/`bytes` (bucket labels, not values),
`class` (error category). Never a title, an email, an account id, or `.ds` bytes.

---

## 9. Verification

- **Collector unit-ish:** signed batches at `source` ∈ {absent, `dse-app`,
  `cloud-backend`, `bogus`} × feature name ∈ {app name, cloud name, unknown};
  assert the stored `source`/`edition` and the 400s. A `sessionStart` eight days
  old must 400 (guards F2 from regressing on the collector side).
- **View invariance:** capture `/analytics?period=year` before Phase B, insert
  synthetic `cloud-backend` rows, re-render, diff — must be identical. This is
  the single highest-value test in the plan.
- **Rollup:** seed >1-year-old rows for both sources, run the aggregation, assert
  two distinct `feature_monthly_aggregates` rows and that a second run is a
  no-op.
- **Emitter (cloud):** the branch's existing tests plus one that advances the
  clock past 7 days and asserts `sessionStart` is re-stamped.
- **End to end:** step 28 above, then a real mutation on pre-prod appearing on
  `/cloud` within one flush interval.

---

## 10. Open items

- **Instance identity across restarts.** `deriveClientID` hashes the hostname —
  stable for a pinned host, but a rescheduled container changes identity and
  fragments the instance breakdown. Acceptable for §5.2's purposes; revisit if
  instance counts start being read as meaningful.
- **SQLite ceiling.** As the ADR flags. Server events are business events, not
  per-request, so the ceiling is distant — but `/cloud` is the page that will
  reveal it first. Worth a row-growth glance after a month of prod data.
- **Rolled-back mutations over-count** (D8). Quantify from pre-prod before
  deciding whether the event-log tail tap is worth building.
