# Cloud Analytics Implementation Plan

Adding cloud-backend product analytics to this service: a `cloud_events` table,
a `POST /api/cloud/events` ingest route, and a `/cloud` dashboard — alongside
the existing desktop-app pipeline, sharing nothing with it but the process.

**Status:** proposed. **Date:** 2026-07-26 (rewritten 2026-07-28).

**The decisions live in the cloud repo's ADR log** (branch
`adr-0035-backend-analytics`), which is where this project's architecture
decisions are recorded — this repo has no ADR practice, and one wouldn't be
worth starting for a single record:

- **ADR-0036 — cloud events get their own table and endpoint.**
  **Authoritative for everything in this repo.**
- **ADR-0035 — backend analytics.** The cloud side: emitter, audit tap, sink
  resolution, event taxonomy. Its emitter exists unwired on branch
  `analytics-emitter` (`internal/analytics/`).

This document is the **evidence and the sequencing**. Where it and an ADR
disagree about *why*, the ADR wins.

> **Rewritten 2026-07-28.** The first version of this plan put cloud events into
> `analytics_events` behind a `source` column. That was reversed before any code
> was written — see ADR-0036 "Considered and rejected", and §3 below for what it
> changed.

---

## 1. Summary

The cloud backend needs somewhere to put server-side product events. This
service is the right host — it already runs, already HMAC-gates ingest, already
has retention, dashboards and a Cloudflare/nginx front, and ADR-0005 says reuse
it. What it should *not* host them in is `analytics_events`, whose twelve
columns describe a desktop installation.

So: a new table, a new route, a new allowlist, a new page. **No existing table,
query, template or job is modified.** That is the property that makes this safe
to ship in one PR ahead of any cloud traffic — there is no shared surface for a
cloud misconfiguration to damage.

---

## 2. What already exists

**This service** (`api/main.go`, 3062 lines, single file). `POST
/api/analytics/batch` (`main.go:1493`) → HMAC (`main.go:929`) → `validateBatch`
(`main.go:870`) → one row per event into `analytics_events` (`main.go:1573`).
Dashboards `/platforms` (reads `version_checks` only) and `/analytics` (six
queries over `analytics_events`, `main.go:1899`). A monthly job rolls
`feature_used` into `feature_monthly_aggregates` and prunes raw rows past a year
(`main.go:1147`–`1237`). Fail-closed feature allowlist loaded from
`features.json` at boot (`main.go:546`, `main.go:1366`).

**The emitter** (cloud, branch `analytics-emitter`). `Emitter` interface,
`httpEmitter` with a bounded channel, periodic + threshold flush, `429` backoff
with re-enqueue, drop-on-full counter, `NopEmitter`, and `Resolve()` for
safe-by-default sink selection. Well built, no call sites. Its wire types
target the desktop contract and will be retargeted (Phase C).

**The tap point** (cloud). `audit.Writer` is an interface constructed in exactly
one place — `internal/server/router.go:59` — and injected into every repository
and handler. One decorator there covers score, folder, tag, share and lock.

---

## 3. Findings

Nine problems came out of reading the two codebases against the original
shared-table design. **Four dissolved** when cloud events got their own table,
and they were exactly the four that failed silently: the dropped `source` field,
`sessionStart` expiring at 7 days, `edition` defaulting to `'studio'`, and the
yearly rollup fusing histories irreversibly. Three design burdens went with them
(`CHECK`-constraint workarounds, scoping eight dashboard queries, threading
`source` through the rollup). ADR-0036 records that argument.

**The five that remain**, all of which this plan still has to handle:

### R1 — the fail-closed allowlist rejects the whole batch
`validateBatch` (`main.go:915`) returns an error for the *batch* when one
feature name is unknown, discarding up to 999 good events. The new endpoint
does better: reject unknown names **per event**, store the rest, return the
rejected count. Fail-closed on data without the blast radius.

### R2 — `features.json` is regenerated at release time
It is a build artefact of dse-mxml's `AnalyticsFeature` enum, scp'd to snare
each release, and **gitignored here** (`.gitignore:14`). Anything hand-added is
deleted on the next release. `cloud-events.json` is therefore a separate,
**committed**, hand-authored file — different lifecycle, different origin.

### R3 — ingest rate budget
`analytics_limit` is `1r/m` keyed on `$http_x_client_id` (`nginx.conf:36`),
sized for a desktop client flushing every 5 minutes. The cloud path gets its own
zone keyed on `$http_x_instance_id` at `6r/m`, so a 60s emitter cadence sits
comfortably inside it. The server already sets `limit_req_status 429`
(`nginx.conf:179`), so the emitter's existing backoff engages correctly.

### R4 — non-429 rejections are invisible
`httpEmitter.send()` discards the response body and returns `sendDrop` on any
non-2xx/429, throwing away the collector's own `{"error":…,"details":…}`. Fixed
emitter-side (Phase C), and made actionable by R1's per-event rejection count.

### R5 — new routes are unreachable unless nginx is told
`nginx.conf` enumerates locations and ends with a deny-all `location /`
(`nginx.conf:378`), inside a server that 444s non-Cloudflare, non-local traffic
(`nginx.conf:162`). **Two** new locations are needed: `/api/cloud/events` and
`/cloud`.

**Also worth knowing:**
- `api/Dockerfile:10` copies **only `main.go`**. Any new `.go` file needs
  `COPY *.go .` or the build silently uses stale code.
- Event timestamps get no clock-skew tolerance in the existing validator
  (`main.go:921`, `> now`) while `sessionStart` gets five minutes. The new
  endpoint gives timestamps the same tolerance.
- The prod collector sits behind Cloudflare with authenticated origin pulls. A
  cloud instance posting to `https://support.drumscore.scot` arrives as a
  Cloudflare IP with a valid cert, so `$allow_access` passes — but **prove it
  with curl from the cloud box** rather than assuming.

---

## 4. Schema

New table only. `CREATE TABLE IF NOT EXISTS` in the existing schema block
(`main.go:690`) — no `ALTER`, no migration, no backfill, nothing to reverse.

```sql
CREATE TABLE IF NOT EXISTS cloud_events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at   DATETIME NOT NULL,
  received_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  instance_id   TEXT NOT NULL,
  cloud_version TEXT,
  event_name    TEXT NOT NULL,
  account_hash  TEXT,
  props         TEXT
);

CREATE INDEX IF NOT EXISTS idx_cloud_events_occurred ON cloud_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_cloud_events_name     ON cloud_events(event_name);
CREATE INDEX IF NOT EXISTS idx_cloud_events_account  ON cloud_events(account_hash);
```

`account_hash` is a real column rather than `json_extract` over `props`: it is
the field every `/cloud` query touches, and it ports to Postgres/YugabyteDB
without a `jsonb` rewrite — relevant given the intent to consolidate the back
end onto the cluster.

`received_at` alongside `occurred_at` costs nothing and answers "was this a
backlog flush or live traffic?" when diagnosing gaps.

No `CHECK` constraints on `event_name`: the allowlist enforces it at ingest, and
a `CHECK` would need a table rebuild to extend.

---

## 5. Ingest — `POST /api/cloud/events`

```json
{
  "instanceId": "<64-hex>",
  "cloudVersion": "1.4.2",
  "events": [
    { "timestamp": 1753600000000,
      "name": "share.minted",
      "accountHash": "<64-hex>",
      "props": { "kind": "view-snapshot" } }
  ]
}
```

Reuses `validateSignature` (`main.go:929`) against `ANALYTICS_SECRET` and
`validateClientID` (`main.go:850`) for the 64-hex `instanceId` / `accountHash`
format.

| Rule | Behaviour |
|---|---|
| Bad signature | `401`, whole batch |
| Malformed JSON / no events / >1000 events | `400`, whole batch |
| `instanceId` not 64-hex | `400`, whole batch |
| `timestamp` outside 7 days (±5 min skew) | drop event, count it |
| `name` not in `cloud-events.json` | drop event, count it |
| `accountHash` present but not 64-hex | drop event, count it |
| otherwise | store |

Response `202`: `{"status":"accepted","eventsReceived":N,"eventsRejected":M}`.

Rejecting per event rather than per batch is the deliberate improvement over the
desktop endpoint (R1) — one unrecognised name must not cost 999 good events.
`M > 0` is logged server-side with the offending names so a taxonomy drift shows
up in the logs, not just in a counter.

`cloud-events.json` (committed, `CLOUD_EVENTS_FILE`, default
`/app/cloud-events.json`), same `name → category` shape as `features.json`,
loaded fail-closed at boot beside it:

```json
{
  "score.created":   "Score",
  "score.updated":   "Score",
  "score.deleted":   "Score",
  "image.stored":    "Image",
  "share.minted":    "Share",
  "viewer.verified": "Share",
  "sync.subscribed": "Sync",
  "error":           "Error"
}
```

Props carry buckets and enums only — `kind`, size/bytes bucket labels, error
class. Never a title, an email, an account id, or `.ds` bytes. Account identity
travels in `account_hash` and nowhere else.

---

## 6. Views

### 6.1 Existing pages: no change

`/analytics` and `/platforms` are **not touched**. Their queries cannot see
`cloud_events`, so the desktop dashboard is protected structurally rather than
by a `WHERE` clause someone must remember to add to the next query they write.

### 6.2 New `/cloud`

Third nav tab, same period selector (`hour|day|week|month|year`), same Chart.js
bucketing.

1. **Summary cards** — Total events · Distinct accounts active · Instances
   reporting · Errors.
2. **Event popularity** — name, category, total events, distinct accounts.
3. **Events over time** — same bucket-format switch as `/analytics`.
4. **Breakdowns** — by `props` enum (share kind, error class) and by instance.

```sql
-- event popularity
SELECT event_name,
       COUNT(*)                        AS total_events,
       COUNT(DISTINCT account_hash)    AS accounts
FROM cloud_events
WHERE occurred_at >= datetime('now', '-7 days')
GROUP BY event_name
ORDER BY total_events DESC;

-- breakdown by a props enum
SELECT json_extract(props, '$.kind') AS kind, COUNT(*)
FROM cloud_events
WHERE event_name = 'share.minted'
  AND occurred_at >= datetime('now', '-7 days')
GROUP BY kind;
```

`json_extract` survives only for low-traffic `props` breakdowns, never for
identity — that is why `account_hash` is a column.

### 6.3 Shared period plumbing

The period → `(label, timeFilter, bucketFormat, granularity)` switch is already
duplicated between `/platforms` and `/analytics`. Extract
`resolvePeriod(period) (periodSpec, error)` and use it in all three, or `/cloud`
becomes a third copy. This is the only refactor of existing code in the plan.

### 6.4 Not built

No combined app+cloud overview. The two populations have different identity
spaces and no shared denominator; the question hasn't been asked.

---

## 7. Retention

Prune `cloud_events` older than a year in the existing monthly job, next to the
`analytics_events` prune (`main.go:1231`):

```sql
DELETE FROM cloud_events WHERE occurred_at < datetime('now', '-1 year');
```

**No monthly rollup.** The desktop rollup exists to reclaim SQLite space at
desktop volumes; server business events are orders of magnitude fewer. Adding
aggregation later is additive — carrying an unused aggregate table is not free.
Revisit if `/cloud` starts wanting year-scale history.

---

## 8. Implementation

### Phase A — collector (this repo)

Purely additive; nothing existing changes. Deployable immediately.

1. `cloud_events` table + indexes in the schema block (§4).
2. `cloud-events.json` committed; `CLOUD_EVENTS_FILE` loaded fail-closed at boot
   beside `features.json`; add to `docker-compose.yml` + `.dev.yml` mounts.
3. `POST /api/cloud/events` handler (§5) — signature, batch validation,
   per-event filtering, insert, `202` with counts.
4. `nginx.conf`: `cloud_events_limit` zone (`$http_x_instance_id`, `6r/m`) and a
   `location /api/cloud/events` block modelled on `nginx.conf:213`.
5. `api/Dockerfile` → `COPY *.go .` if the handler goes in a new file.
6. Prune statement in the monthly job (§7).

### Phase B — the `/cloud` view (this repo)

7. `resolvePeriod` extraction (§6.3).
8. `/cloud` handler + `api/templates/cloud.html`.
9. Nav third tab in `analytics.html:297`, `platforms.html:297`, `cloud.html`.
10. `location /cloud` in `nginx.conf`, modelled on `nginx.conf:274`.

B can lag A — with A deployed, correctly-shaped data accrues whether or not
anyone is looking at it. It cannot lag *far*, or the first thing anyone learns
about a taxonomy mistake is a month of bad rows.

### Phase C — emitter (cloud, branch `analytics-emitter`)

11. Retarget wire types at §5's shape. This **deletes** the `sessionStart`, `os`
    and `edition` plumbing; `AccountHash` moves from `props` to a first-class
    per-event field.
12. `FlushInterval` 60s; `BatchThreshold` 500; `MaxBatch` 500.
13. Retain the first ~512 bytes of a non-2xx body in the log; add a `rejected`
    counter beside `dropped`; log the `eventsRejected` count from `202`s.
14. Emit product events only — no session events.

### Phase D — cloud wiring

15. `ANALYTICS_*` in `internal/config` via the existing `envDefault`/`envBool`
    idiom; `Resolve` + `New` at boot; `Close` on the graceful-shutdown path.
16. `auditEmitter` decorator wrapping `audit.Writer`, injected at
    `internal/server/router.go:59`. Maps audit `Operation` values to event names
    — close to identity, since both use `score.created` / `share.minted` form.
17. Direct emits for non-audited signals (viewer verify, sync subscribe).
18. `ACCOUNT_HASH_SALT` in config, stable per deployment, treated as a secret.

### Phase E — rollout

19. Deploy A (+B) to snare. Confirm `/analytics` and `/platforms` are unchanged
    and `/cloud` renders empty.
20. Stand up / point at a non-prod collector for pre-prod; confirm the
    bare-launch default actually connects.
21. Signed `curl` of a cloud batch **from the cloud host** to prod — proves the
    Cloudflare origin-pull path before anything depends on it.
22. Enable in pre-prod; watch `dropped` / `rejected` / `eventsRejected` at zero
    for 24h.
23. Point prod at prod (URL *and* secret, per ADR-0035 §5).

**Ordering:** A blocks C/D. Everything else is soft.

---

## 9. Verification

- **Ingest:** signed batches covering each row of §5's table; assert the stored
  row and the `eventsRejected` count. Specifically: a batch with one unknown
  name stores the rest and reports `1` — the regression test for R1.
- **Isolation:** insert `cloud_events` rows, re-render `/analytics?period=year`
  and `/platforms`, diff against a capture taken before Phase A. Must be
  identical. This is the highest-value test here, and it should stay in place as
  a guard, not just run once.
- **Fail-closed boot:** missing or empty `cloud-events.json` must refuse to
  start, matching `features.json` behaviour (`main.go:1370`).
- **Retention:** seed rows older than a year, run the job, assert they are gone
  and that `analytics_events` and the aggregate tables are untouched.
- **Emitter (cloud):** existing branch tests retargeted; one asserting a full
  buffer drops rather than blocks.
- **End to end:** step 21, then a real pre-prod mutation appearing on `/cloud`
  within one flush interval.

---

## 10. Open items

- **Instance identity across restarts.** `deriveClientID` hashes the hostname,
  so a rescheduled container becomes a new instance and fragments the per-
  instance breakdown. Fine for the counts wanted now; revisit if instance counts
  start being read as meaningful. (ADR-0035 OQ4.)
- **Rolled-back mutations over-count.** The audit decorator emits inside the
  caller's transaction, so a rolled-back mutation still emits. Accepted as
  best-effort; quantify from pre-prod before deciding whether to move the tap to
  the committed event-log tail.
- **SQLite ceiling / cluster consolidation.** `cloud_events` is shaped to port
  to a relation cleanly. Don't pre-build for it — no storage abstraction over
  SQLite in `main.go`; the storage layer gets rewritten whenever that migration
  happens, and speculative indirection now would be the wrong shape.
