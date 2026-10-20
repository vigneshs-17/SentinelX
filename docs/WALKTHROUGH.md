# Walkthrough: one SYN packet from the NIC to the dashboard

For a reader who knows Python and basic networking but not this code. Every reference has the form `path:line` followed by the symbol on that line;
`tests/test_phase8_docs.py` checks that each one still points at its symbol, so a stale reference fails the test suite.

Story: host `10.0.0.9` sends a TCP SYN to `10.0.0.5:22`. It is the 10th distinct port that host has probed on `10.0.0.5` within 10 seconds, so a vertical port scan alert fires.

## Part 1: the sensor process

1. **Start.** `python main.py sensor` calls `main.py:210` — `def handle_sensor`, which builds a `Sensor` and runs it. `capture/sensor.py:123` — `def start` creates or upgrades `alerts.db` and starts the heartbeat and retention threads. (A PCAP replay takes `capture/pcap_replay.py:10` — `def replay_pcap` instead of sniffing, and feeds the same pipeline.)
2. **Capture.** `capture/packet_capture.py:55` — `sniff(` asks Scapy for packets. Its callback is `PacketPipeline.enqueue`, so the capture thread does almost nothing per packet.
3. **Enqueue.** `capture/pipeline.py:70` — `def enqueue` counts the packet as received and calls `capture/pipeline.py:78` — `put_nowait(packet)`. If the queue is full the packet is dropped and counted, never waited on. This is the only place packets are lost on purpose.
4. **Consume.** One thread runs `capture/pipeline.py:93` — `def _worker_loop`. It takes a packet from the queue and calls `capture/pipeline.py:106` — `self.processor(item)`. An exception is counted and logged; the loop continues.
5. **Process.** `capture/processor.py:53` — `def process` is the per-packet entry. It first calls `capture/processor.py:60` — `parse_packet(packet)`.
6. **Parse.** `capture/packet_parser.py:6` — `def parse_packet` turns a Scapy packet into a plain dict: `ts` (the packet timestamp), addresses, ports, size and TCP flags. A SYN is `capture/packet_parser.py:74` — `packet_data["tcp_syn"] = is_syn and not is_ack`: SYN set, ACK clear. A packet with no timestamp is counted as a parse error and skipped.
7. **Engine.** `capture/processor.py:78` — `self.engine.process_packet` hands the dict to `detection/engine.py:52` — `def process_packet`. The engine moves its clock to the packet time, never backwards: `detection/engine.py:62` — `self.clock = event_ts`. It then calls `observe()` on each of the five detectors in order and collects any alerts. Every ten seconds of event time it also evicts expired state.
8. **Detector.** For our packet, `detection/detectors/port_scan.py:26` — `class VerticalPortScanDetector` does the work (see "Vertical-scan window" below). It drops the old ports at `detection/detectors/port_scan.py:59` — `cutoff = event_time - self.window`, adds port 22, and compares at `detection/detectors/port_scan.py:80` — `if unique_port_count >= self.threshold`. Cooldown checks use `detection/detectors/base.py:32` — `def is_in_cooldown`. The result is built at `detection/detectors/port_scan.py:100` — `alert = Alert(` with its evidence dict. Severity and confidence come from `detection/scoring.py:11` — `def calculate_severity`.
9. **Emit.** Back in the processor, `capture/processor.py:46` — `def _emit` counts the alert and calls the alert sink. In the sensor that sink is `logs/sinks.py:173` — `class CompositeSink`, called through `logs/sinks.py:192` — `def __call__`. It normalises the record once and fans it out to the JSONL file, SQLite and (if configured) the webhook. One failing sink cannot stop the others.
10. **Persist.** SQLite insert: `database/database.py:145` — `def insert_alert`, one parameterised `INSERT`, guarded by a writer lock, in WAL mode. JSONL append: `logs/alert_logger.py:93` — `def append_jsonl`.
11. **Heartbeat.** Separately, `capture/sensor.py:94` — `def write_status` writes a `sensor_status` row every few seconds with received, dropped, queue depth, pps and state size. The API's health view reads those rows.

The sensor never serves HTTP. Its only output is the two files.

## Part 2: the API process

12. **Read-only door.** `database/database.py:112` — `def get_readonly_connection` opens `alerts.db` with SQLite `mode=ro`. Any write through it raises an error.
13. **Gate.** Every route passes `backend/auth.py:79` — `def require`: no valid session cookie or API key means 401, a role without the permission means 403.
14. **List.** The console calls `GET /api/v1/alerts`, served by `backend/api.py:376` — `def get_alerts`: validated filters, allow-listed sort column, bound parameters, a join with the triage table in `app.db`.
15. **Live updates.** `backend/api.py:718` — `class AlertStream` sends a Server-Sent Event every few seconds with the ids of new alerts (`backend/api.py:736` — `def _snapshot`). If streams are capped or fail the browser polls instead.

## Part 3: the browser

16. `dashboard/static/js/stream.js:32` — `function handleEvent` receives the event and, when it lists new ids, fetches the new alerts through the normal API.
17. `dashboard/static/js/views/common.js:18` — `export function alertRow` builds a table row with DOM calls and `textContent`; alert text is never parsed as HTML.

## Worked examples

### Vertical-scan window

Use threshold 3 and window 10 s to keep the numbers small (defaults are 10 and 10 s). State for key `(10.0.0.9, 10.0.0.5)` is a dict of `port -> last SYN time`.

| Event time | SYN to port | `cutoff = t - 10` | Ports kept (`ts >= cutoff`) after adding | Count | Alert? |
| --- | --- | --- | --- | --- | --- |
| 0 | 22 | -10 | {22} | 1 | no |
| 4 | 80 | -6 | {22, 80} | 2 | no |
| 9 | 443 | -1 | {22, 80, 443} | 3 | **yes** |

If the third SYN had arrived at t=11, the cutoff would be 1, port 22 (seen at 0) would be dropped, and the count would be 2 (80 and 443): no alert. That is the whole difference between a fast scan and a slow one; the slow-scan detector uses the same idea with a 300 s window and a threshold of 20. After an alert, a 30 s cooldown for the same (source, target) stops a repeat on every further port.

The dict is capped at `threshold + 1` ports (`detection/detectors/port_scan.py:69` — `elif len(ports) < (self.threshold + 1)`), so one source cannot make one entry grow without bound.

### LRU state store

`detection/state_store.py:14` — `class BoundedStateStore` is an ordered dict with a size cap. Cap 3, operations in order:

1. `put A`, `put B`, `put C`: order A, B, C.
2. `get A`: A is moved to the end: order B, C, A.
3. `put D`: the store is full, so the first (least recently used) entry B is removed at `detection/state_store.py:59` — `popitem(last=False)`: order C, A, D.

Memory is therefore bounded by the cap, and an attacker who invents source addresses only pushes out the oldest entries of that one detector's partition. Entries also expire by event time (`evict_expired`), so a quiet table drains when traffic resumes.

### SYN-flood ratio

Defaults: threshold 100 SYN/s, window 5 s, completion ratio limit 0.2. The detector counts, per (destination, port), SYNs and the ACKs that complete a remembered half-open connection (`detection/detectors/syn_flood.py:96` — `self.half_open.put`). The decision is `detection/detectors/syn_flood.py:133` — `completion_ratio = ` `total_acks / total_syns`.

| Case | SYNs in the first second | Completed handshakes | Rate | Ratio | Alert? |
| --- | --- | --- | --- | --- | --- |
| Busy web server | 120 | 100 | 120/s | 0.83 | no (ratio above 0.2) |
| Flood with a few leaks | 120 | 12 | 120/s | 0.10 | **yes** |
| Quiet scanner | 30 | 0 | 30/s | 0.00 | no (rate below 100) |

Both conditions are needed: a high rate alone is also what a popular server looks like, and a low ratio alone is what a few failed connections look like. In the benchmark's spoofed-flood scenario the 100th SYN arrives at 0.5 s with no ACKs, so the alert fires at 0.5 s (the report's SYN_FLOOD time-to-detect).

## Fifteen questions you may be asked

1. **Why not ML only?** There was ML, and it was circular: trained on data made by the same rules it confirmed, so it measured nothing. A rule is checkable by reading it; a model needs real labelled traffic, which I could not run. ML is optional, additive and off until a signed gate says it beat rules-only on held-out data.
2. **What evades your detectors?** Scans below the thresholds or slower than 300 s; non-SYN probes (FIN, NULL, UDP); many sources each staying under the limit; completing handshakes in a connection flood; ramping volume slowly so the EWMA baseline follows. The README table lists each.
3. **How do you know your numbers are real?** The benchmark table is copied by `scripts/gen_readme_results.py` from `eval_output/report.md`, produced by one command at a recorded commit, and CI runs it. But they are synthetic scenarios I wrote, so they prove regression safety, not real-world accuracy.
4. **Why event time instead of the system clock?** Replaying a capture at full speed made benign 10 pps traffic look like a flood under wall-clock windows. Packet time makes results identical on any machine and testable with exact counts. Cost: state only ages when packets arrive.
5. **Why one engine thread?** The detectors keep shared state and assume per-source order; more threads gave no speed-up under the GIL and could reorder packets. Cost: one core is the ceiling.
6. **What happens at overload?** The queue is bounded; excess packets are dropped and counted, and the health view warns above a drop ratio. Dropped packets are never analysed.
7. **How is memory bounded?** Every table keyed by an attacker-controlled value is a capped LRU store with event-time expiry, partitioned per detector so a flood against one cannot evict another's state.
8. **Why SQLite and not Postgres?** One writer (the sensor) and a few readers; WAL handles that with no server to run. Revisit for several sensors.
9. **Why split sensor and API?** Capture needs raw-socket privilege; a web server should not have it. The API opens the alert database read-only and can be restarted without losing packets.
10. **How are passwords and sessions handled?** Argon2id hashes; random session tokens of which only a hash is stored; idle and absolute timeouts; lockout with growing delay; CSRF token plus Origin check; API keys stored hashed.
11. **How do you stop XSS from packet-derived text?** The console never parses markup: it builds DOM nodes and sets `textContent`. A test scans the static files for markup-parsing APIs, and the CSP forbids inline script.
12. **What if the webhook receiver is down?** Delivery is on its own thread with a bounded queue, retries with backoff and per-source dedup. The engine never waits; failures are counted and shown in health. The URL is treated as a secret and never logged.
13. **Why did ML get removed from the alert path?** See question 1. The gate, the signing of the model file and the leakage-safe splits exist so that if real data later supports it, the claim can be checked.
14. **What would you do with more time?** Run the real-data pipeline and publish the result honestly; study false positives on real home traffic; shard the engine by source; share rate-limit state between API processes.
15. **What did you not verify?** Hosted CI runs of the container, fuzz, ZAP, secret-scan and browser jobs; a screen-reader pass; real-traffic accuracy of anything; Docker on Linux. The final checklist in `docs/PROGRESS.md` lists the exact commands.
