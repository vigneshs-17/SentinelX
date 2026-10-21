# Design decisions

Each section: the decision, what it replaced or was weighed against, why the alternatives lost, and the cost we accepted. Defect IDs (D1-D15) refer to the
independent audit of the v1 code, summarised in `docs/history/2026-09-audit.md` and mapped to fixes in `CHANGELOG.md`.

## 1. Event time, not wall-clock time (D1)

**Decision.** Every detector window, cooldown, TTL and the ML flow table runs on the timestamp carried by the packet (`packet.time`). The engine keeps a
monotonic event clock that only moves forward (`detection/engine.py`, `DetectionEngine.process_packet`). Nothing under `detection/` calls `time.time()`,
`time.monotonic()` or `datetime.now()`; a test (`tests/test_phase3_regression.py`) parses the source and fails if one appears.

**Alternatives.**
- *Wall clock (v1).* Simple, but PCAP replay compresses time: benign 10 pps traffic spread over 120 s was flagged `HIGH_TRAFFIC` because replay ran fast. Results then
  depend on CPU speed and cannot be reproduced.
- *Hybrid (wall clock live, packet time in replay).* Two code paths means live behaviour is never what the tests exercised.

**Why event time won.** The same packets give the same alerts on any machine at any speed; the benchmark in README Results is therefore reproducible, and the
scenario suite can assert exact alert counts.

**Cost.** State only ages when packets arrive. A quiet network never advances the clock, so idle state is only evicted on the next packet (the engine prunes
opportunistically every 10 s of event time). Out-of-order packets are processed with their own timestamp but cannot move the clock back, so a badly reordered capture
can briefly skew a window. Live capture trusts the kernel timestamp.

## 2. One engine thread, not worker threads (D8)

**Decision.** Capture (producer) puts packets on a bounded queue; one consumer thread parses, runs the detectors, and writes alerts (`capture/pipeline.py`).

**Alternatives.**
- *N worker threads (v1 `--workers`).* Not measured in this repository. CPython's GIL stops threads running Python code in parallel, v1's workers shared global locks (D8: the
  multi-worker mode was not really parallel), and a worker could reorder one source's packets, which breaks window logic that assumes order per source.
- *Multiprocessing by source hash.* Would scale, but needs cross-process state for detectors that look at a destination (SYN flood, volumetric) and for the
  per-source ML context. Not built; it is the upgrade path if one core is not enough.

**Why one thread.** Deterministic, ordered, no locking inside detectors. The README Results section gives the replay throughput measured over three runs on one machine; whether that
is enough depends on your link's packet rate, which you can read from `pps_10s` in the health view (see OPERATIONS.md, "Packets are being dropped").

**Cost.** A hard ceiling of one core. When the queue is full, packets are dropped and counted (`dropped` in the sensor heartbeat); the health view warns above
`SENTINELX_DROP_WARN_RATIO`. The engine is never allowed to block capture.

## 3. Bounded state with LRU eviction (D3, D9)

**Decision.** Every table an attacker can grow by choosing source addresses is a capped, partitioned LRU store (`detection/state_store.py`): one partition per detector,
a cap per partition, event-time TTL pruning. A flood of spoofed sources evicts only its own detector's oldest entries, not another detector's state.

**Alternatives.** One shared table (a spoofed-source flood would evict SYN-flood aggregates); unbounded dicts with periodic cleanup (v1: tables grew with every new
source address and had no cap; no memory figure is claimed here); a database for state (latency on the packet path).

**Cost.** An attacker can force eviction of the oldest entries in a partition. For a scan detector that means a slow scan that is interleaved with a flood of
other sources can lose its history. The cap values are configurable (`SENTINELX_CAP_*`), and `evictions` is reported so it is visible.

## 4. SQLite with versioned migrations, not an ORM

**Decision.** Plain `sqlite3`, WAL mode, schema versions tracked with `PRAGMA user_version`, ordered migration functions (`database/migrations.py` for `alerts.db`,
`database/app_db.py` for `app.db`). Queries are parameterised SQL; dynamic parts (sort column, filter conditions) come from fixed allow-lists.

**Alternatives.** SQLAlchemy + Alembic (two dependencies and an abstraction over a schema of a handful of tables); a JSON file (v1's other store: no queries, no
indexes). Postgres is discussed in section 8.

**Why.** The schema is small, the access patterns are known, and the migration tests (`tests/test_phase2_regression.py`, `test_phase3_regression.py`,
`test_phase7a_api.py`) upgrade real older-version databases.

**Cost.** Hand-written SQL needs care (see the bandit `# nosec B608` lines: each is an f-string over fixed fragments with every value bound). SQLite allows one writer at a time;
that is fine for one sensor and one API (see section 8).

## 5. Split processes: sensor and API (D13)

**Decision.** `main.py sensor` captures, detects and writes `alerts.db`; `main.py api` serves the console and REST API, opens `alerts.db` read-only
(SQLite `mode=ro`) and owns `app.db`. The API needs no capture privilege. In Docker they are separate containers with different capabilities.

**Alternatives.**
- *One process with Flask in a thread (v1).* The packet-capture process needs root/admin; running a web server and parsing HTTP inside it makes every web bug a
  root bug. v1 also served the dev server on a non-loopback address with no authentication.
- *A message queue or RPC between them.* More moving parts to fail. The SQLite WAL file is already a durable, ordered interface that both sides understand.

**Why.** Least privilege (the API cannot write alerts: tested), independent restarts (the sensor keeps recording while the API is down), and a clean place to
put authentication.

**Cost.** The API sees alerts with a small delay and polls the database (live updates are a 2 s tick, not push from the sensor). Triage state lives in a
different database than alerts, so the API attaches `app.db` read-only to join them in a query.

## 6. Authentication choices

**Decision.** Server-side sessions (random 256-bit token, only its SHA-256 stored, idle and absolute timeouts), Argon2id passwords, CSRF token plus Origin check
for cookie sessions, separate hashed API keys for scripts, default-deny route policies (`backend/auth.py`).

**Alternatives.** JWTs (cannot be revoked before expiry without a server-side list, which is a session table anyway); HTTP basic auth (no logout, credentials on
every request); trusting the network (v1).

**Cost.** Every authenticated request touches `app.db` (session lookup, last-seen update). Rate limits and login lockouts are in memory per process, so they reset on
restart and are not shared across several API processes.

## 7. The ML model and its gate (D5, D12)

**Decision.** v1's model was removed: it was trained on synthetic data generated by the same rules it was meant to confirm (circular). The replacement is a
flow-level gradient-boosted classifier trained and tested on real labelled traffic, **allowed into the alert path only if it passes a pre-declared gate**: on a held-out
replay, rules+ML must beat rules-only on recall by a margin at equal or lower false alerts per benign hour. ML can only add alerts, never suppress a rule alert.
The model file is signed (HMAC-SHA256) and loaded with `skops` and an explicit type list; a signed gate file bound to the model hash must say PASS.
**What the signature proves:** only that the model and gate files were not altered after the key holder signed them (protection against file tampering). It does not prove the key holder
ran an honest evaluation: whoever holds `SENTINELX_MODEL_KEY` can sign a PASS for any model. The gate is a process control, not a proof.

**Result.** **NOT RUN.** The CIC-IDS2017 PCAPs were not available on the build machine, so no model was evaluated and ML stays off. See `docs/ML_REPORT.md`
(generated from JSON; it contains no hand-typed numbers) and `docs/DATASET.md` for the exact procedure.

**Alternatives.** Keep the packet-level model (circular, an ordinary client SYN to :443 scored as a port scan); random train/test split (flows from one attack leak across
the split, inflating scores); score the model on a CSV someone else labelled (label errors); load a pickle after checking a hash stored next to it (detects corruption, not tampering).

**Cost.** Today the project ships a pipeline and no accuracy claim for ML. That is the honest state.

## 8. Why not Kafka, Postgres or Kubernetes at this scale

The deployment unit is one sensor on one host and one API. The measured packet throughput of the single engine thread is in README Results (generated by
`python main.py eval`), alert volume is low (alerts are rate-limited by cooldowns), and the working set of detector state is capped in memory.

- **Kafka** would add a broker, partitions and consumer management to move a few alerts per second between two processes that already share a file.
- **Postgres** would add a server, credentials and backups to store a small, append-mostly table written by one process. SQLite WAL gives concurrent readers with one
  writer, which is exactly the shape here, and runs with no setup.
- **Kubernetes** would orchestrate a sensor that must sit on a specific network interface (`network_mode: host`) and a stateful single-writer database;
  compose already expresses that.

**When to revisit.** Several sensors writing to one store (use Postgres or a collector in front), sustained traffic beyond one core (shard by source and share
destination state), or a multi-host deployment (then orchestration pays for itself).

## 9. Console: vanilla JavaScript modules, SSE, server paging

No framework or bundler: the console is about 90 KB of JS and CSS, needs no build step, and runs under a CSP with no `unsafe-inline` and no external origins.
Live updates use Server-Sent Events (one direction, plain HTTP, works through proxies, capped at 8 streams per process because each holds a thread) with a polling
fallback. Tables are paged on the server (50-500 rows) rather than virtualised in the browser, which keeps the DOM small and the filters, sorting and export
consistent because they share one query builder.

## 10. Scan detectors count only attempts that did not complete a handshake

**Decision.** `detection/handshakes.py` records each SYN (`scan_attempts`) and, when the client's ACK follows, remembers that (source, destination, port) completed (`scan_completed`). The vertical,
horizontal and slow-scan detectors drop completed destinations before comparing with their threshold. Unanswered SYNs, RST-answered SYNs and SYN-ACKs that the client never ACKs (a half-open SYN scan) still count.
Both tables are capped partitions and use packet time only.

**Why.** A live capture of normal browsing (many tabs, each connecting to a different server on port 443, IPv6 with NAT64 destinations) raised a `HORIZONTAL` alert: 10 hosts on one port in 10 s is what a sweep looks like by
count alone. A browser completes the handshake; a scanner mostly does not.

**Alternatives.** Wait for an outcome before counting (adds latency and misses a scan that ends inside the grace period). Whitelist port 443 (an attacker scans 443 too).

**Cost.** A SYN counts until its ACK arrives, so 10 or more connections to different hosts opened within one round trip can still alert before they complete. A `connect()` scan of open ports completes handshakes and
is not counted for those ports; closed ports (RST) still count. If the capture never sees the client's ACKs (a one-way mirror of the server side), nothing is treated as completed and browsing alerts as before.
