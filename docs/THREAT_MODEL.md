# Threat model

Scope: SentinelX v2 as shipped in this repository: one sensor process, one API/console process, two SQLite files, an optional webhook, and an optional signed ML model.
It does not cover the monitored network itself, the host operating system, or a hostile operator with shell access to the host.

## Assets

| Asset | Why it matters |
| --- | --- |
| Detection integrity (alerts are real, none silently suppressed) | The product's only job. |
| `alerts.db` / `alerts.jsonl` | Evidence of what was seen; may contain internal IPs and ports. |
| `app.db` | Password hashes, session and API-key hashes, triage notes, the audit log. |
| User passwords, session cookies, API keys | Access to alert data and triage. |
| Webhook URL | Usually embeds a secret token. |
| `SENTINELX_MODEL_KEY` and the model file | Whoever holds the key can make the alert path run attacker-chosen model weights. |
| Sensor availability | A sensor that is down or overloaded sees nothing. |

## Trust boundaries

```
 network  -->  [1] NIC -> sensor  -->  [2] sensor -> alerts.db  -->  [3] alerts.db -> API  -->  [4] API -> browser
                                          \--> [5] sensor -> webhook (egress)         app.db (API only)
```

1. **NIC to sensor:** untrusted packets from anyone who can send traffic the sensor sees.
2. **Sensor to database/files:** a local trust boundary between the privileged sensor and the files it writes.
3. **Database to API:** the API process reads data produced from untrusted packets and writes only `app.db`.
4. **API to browser:** the network between a user and the console (usually localhost or a reverse proxy).
5. **Webhook egress:** alert content leaves the host to a URL the operator configured.

## STRIDE per boundary

### 1. NIC to sensor (untrusted packets)

| | Threat | Mitigation (file) | Status |
| --- | --- | --- | --- |
| S | Spoofed source IPs make attacks look like someone else, or blame an innocent host. | None possible at this layer; alerts record the claimed source. | **Accepted.** Spoofing is visible as a SYN flood with low handshake completion (`detection/detectors/syn_flood.py`). |
| T | Crafted packets that crash the parser. | The parser guards the timestamp, length and layer checks it anticipates and returns a partial record (`capture/packet_parser.py`); it does not wrap every field access. Any exception raised while processing one packet is caught in the consumer loop, counted and logged, and the loop continues (`capture/pipeline.py`). Not fuzzed. | Mitigated for crashes of the consumer loop; parser robustness against crafted packets is not measured. |
| R | Attacker denies an event. | Event-time timestamps and evidence fields in each alert (`detection/alert.py`); JSONL + SQLite copies. | Mitigated for what was seen. |
| I | Packet contents leaking via alerts. | Only headers and counters are parsed; payload is not stored. | Mitigated. |
| D | Flooding the sensor: memory growth, queue saturation, CPU. | Bounded queue with drop counter (`capture/pipeline.py`); capped, partitioned LRU state (`detection/state_store.py`); capped flow table (`ml/flows.py`). | Mitigated for memory; **CPU is a real limit** (single thread): sustained overload drops packets and detections are missed. The health view warns. |
| E | Parser bug leading to code execution in a privileged process. | Scapy dissection is the main exposure; the container runs non-root with only `NET_RAW` and a read-only root filesystem (`Dockerfile`, `docker-compose.yml`); live capture inside the container is not tested in CI. | Reduced, not eliminated. |
| - | **Evasion** (the detector never fires). | See the evasion column in README's detector table. | **Residual risk**: slow, distributed, non-SYN scans and encrypted application attacks are not detected. |

### 2. Sensor to files

| | Threat | Mitigation | Status |
| --- | --- | --- | --- |
| T | Another local user edits `alerts.db`. | File permissions of the data directory (operator); containers use a dedicated volume. | **Operator responsibility.** No signing of alert rows. |
| T | Webhook or API consumer tampering with stored alerts. | The API opens `alerts.db` read-only (`database/database.py: get_readonly_connection`); test `test_api_connection_is_read_only_and_never_creates_the_database`. | Mitigated. |
| R | Alerts altered after the fact. | JSONL copy is append-only with rotation (`logs/alert_logger.py`); not tamper-evident. | Partial. |
| D | Disk filled by alerts. | Retention by ingest time (`SENTINELX_RETENTION_DAYS`, live sensor only, never in `replay`), JSONL rotation, capped alert cooldowns. | Mitigated. |
| E | ML model file swapped for a malicious one. | HMAC-SHA256 over the file checked before loading, `skops` with an explicit allow-list, signed PASS gate bound to the model hash (`ml/artifact.py`); ML off by default. | Mitigated for file tampering only. The signature proves the files were not changed after signing; it does **not** prove the key holder evaluated honestly. **Not** mitigated if the signing key or training host is compromised. |

### 3. Database to API

| | Threat | Mitigation | Status |
| --- | --- | --- | --- |
| T | SQL injection through filters. | Values are bound parameters; sort columns and filter keys come from fixed allow-lists; `source_ip`/`destination_ip` are parsed with `ipaddress` (`backend/api.py`). Schemathesis fuzzing runs in CI. | Mitigated. |
| I | Stored XSS: alert fields (attacker-influenced strings) rendered in the console. | Console builds DOM with `textContent` only; no HTML-string sink exists (test `test_no_markup_parsing_or_code_evaluating_apis_anywhere_in_static`); CSP forbids inline script. | Mitigated. |
| I | CSV export abused for spreadsheet formula injection. | Cells starting `= + - @` tab or CR get a leading quote (`backend/api.py: csv_safe`); browser test downloads a payload. | Mitigated. |
| D | Expensive queries. | Page size and offset capped, export capped (`SENTINELX_EXPORT_MAX_ROWS`), graph capped, request rate limited. | Mitigated. |

### 4. API to browser

| | Threat | Mitigation (file) | Status |
| --- | --- | --- | --- |
| S | Credential stuffing, password guessing. | Argon2id; lockout per IP and per username with growing delay; generic error and dummy-hash verification so timing does not reveal which users exist (`backend/auth.py`, `backend/passwords.py`); login rate limit. | Mitigated. Lockout state is per process and in memory. |
| S | Session fixation or theft. | New session id every login, only the token hash stored, HttpOnly + SameSite=Strict cookie, Secure when `SENTINELX_HTTPS=true`, idle and absolute timeouts, revoke-all by an admin (`backend/accounts.py`). | Mitigated; a stolen live cookie works until it expires or is revoked. |
| T | Cross-site request forgery. | CSRF token header on every cookie-authenticated write, Origin check, no CORS (`backend/auth.py`, `backend/api.py`). | Mitigated. |
| R | A user denies a triage change or key creation. | Append-only audit log enforced by SQLite triggers; records actor, source IP, UTC time, target (`database/app_db.py`). Passwords, tokens, keys and the webhook URL are never logged (test `test_no_secret_ever_reaches_logs_audit_table_or_api_responses`). | Mitigated. An attacker with write access to the file can still replace it. |
| I | Data exposed to anyone who can reach the port. | Default deny with a role table (`PERMISSIONS`), full route-by-principal matrix test, bind to `127.0.0.1` by default, Docker publishes on `127.0.0.1` only. | Mitigated. **Plain HTTP unless the operator puts TLS in front.** |
| D | Request floods, many open streams. | Token-bucket rate limit per identity/IP, stream cap with polling fallback, 64 KiB body cap. | Mitigated per process. |
| E | Role escalation. | One decorator enforces permissions server-side; the UI hiding a button is cosmetic. Only admins manage users and keys; the last enabled admin cannot be disabled. | Mitigated. |
| - | Clickjacking, MIME sniffing, referrer leakage. | CSP `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, COOP/CORP. ZAP baseline in CI. | Mitigated. |

### 5. Webhook egress

| | Threat | Mitigation | Status |
| --- | --- | --- | --- |
| I | Alert content (internal IPs, ports) leaves the host. | Opt-in only (`SENTINELX_WEBHOOK_URL`); `slack` and `discord` modes send a one-line summary, `generic` sends the whole alert. | **Operator choice.** |
| I | The URL (a secret) leaks through logs, errors or the API. | Held only in a private attribute, excluded from `repr`, exceptions logged by class name only, never returned by any endpoint (tested). | Mitigated. |
| D | A slow or dead receiver stalls detection. | Background thread, bounded queue, 3 retries with backoff, per-(type, source) dedup; the engine thread never waits (tested). | Mitigated. |
| S/T | An attacker who can set the environment points the webhook elsewhere. | Out of scope: control of the sensor's environment is control of the sensor. | Accepted. |

## Supply chain and build

- Dependencies are pinned; `pip-audit` runs in CI (runtime requirements). Container images are scanned with Trivy for fixable HIGH/CRITICAL findings, the repository
  with gitleaks, the running API with Schemathesis and the OWASP ZAP baseline.
- The model-signing key never lives in the repository; the CI model is a smoke model that is never gate-eligible.

## Residual risks (what this model does not close)

1. **Detection evasion.** The rules are heuristics over TCP SYN, rates and ratios (see README, Detectors). Slow or distributed scans below the thresholds, non-TCP scans and
   attacks inside established connections are invisible to them.
2. **Single-core ceiling.** Overload drops packets; dropped packets are not analysed.
3. **Host compromise.** Anyone who controls the host, the sensor's environment, the data directory or the signing key defeats most controls here.
4. **No TLS built in.** Sessions and API keys travel in clear text unless a reverse proxy terminates TLS.
5. **Per-process limits.** Rate limits and lockouts are not shared between several API processes and reset on restart.
6. **ML has no measured accuracy.** The real-data gate has not been run; ML is off and its role is additive only.
7. **Alert rows are not signed.** File permissions protect the database; the audit log and alerts are not cryptographically tamper-evident.
