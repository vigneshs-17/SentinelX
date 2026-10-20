# SentinelX v2 finish: progress

Driver: Phases 6a-8, one step at a time, in order. Resume at the first unfinished step.
Gates after every step: pytest (coverage >= 82%), ruff check, ruff format --check, mypy, bandit, pip-audit,
and `python main.py eval --scenarios all --out eval_output` must PASS with F1 = 1.0.

Phase 5 real-data ML gate: NOT RUN (CIC-IDS2017 PCAPs not on this machine). Separate task, does not block these steps.

| Step | Scope | Status | Date | Gate result | Open issues |
| --- | --- | --- | --- | --- | --- |
| 6a | Process split, waitress, retention, sensor health, notifications | DONE (committed on v2-upgrade) | 2026-10-20 | pytest 209 passed, cov 88.38% (gate 82); ruff, ruff format --check, mypy (44 files), bandit, pip-audit clean; eval PASS F1=1.0 | Waitress + read-only WAL under a read-only Docker mount is CI/Docker-only (6c); no auth until 6b |
| 6b | Authentication, authorization, audit log | DONE (committed on v2-upgrade) | 2026-10-20 | pytest 242 passed, cov 89.89% (gate 82); ruff, ruff format --check, mypy (50 files), bandit, pip-audit clean; eval PASS F1=1.0; live waitress login/CSRF smoke OK | Dashboard HTML still uses the old unauthenticated fetches until 7a; rate limiting, CSP, /api/v1 move, X-Forwarded-For handling land in 6c |
| 6c | API hardening, OpenAPI, Schemathesis, ZAP, Docker, CI | DONE (committed on v2-upgrade) | 2026-10-20 | pytest 273 passed, cov 90.15% (gate 82); ruff, ruff format --check, mypy (51 files), bandit, pip-audit clean; eval PASS F1=1.0 | Hosted-CI runs of the new jobs not seen (workflow YAML parsed only); dashboard still has no login UI until 7a |
| 7a | Console: login, overview, live, alert list, detail drawer | DONE (committed on v2-upgrade) | 2026-10-20 | pytest 286 passed, cov 90.31% (gate 82); ruff, ruff format --check, mypy (51 files), bandit, pip-audit clean; eval PASS F1=1.0; JS+CSS 60,430 bytes (budget 204,800) | Brush drag, lockout countdown, polling fallback, focus trap, key 'a' and 10k-row behaviour not exercised in a browser yet (Playwright tests are 7c); no axe audit yet |
| 7b | Console: attack graph, sensor health, admin, export | DONE (committed on v2-upgrade) | 2026-10-20 | pytest 298 passed, cov 90.5% (gate 82); ruff, ruff format --check, mypy (51 files), bandit, pip-audit clean; eval PASS F1=1.0; JS+CSS 90,682 bytes (budget 204,800) | Brush drag, lockout countdown, polling fallback, focus trap, 'a' key, 10k-row behaviour and axe/contrast audit still pending for 7c; admin reset-password dialog not clicked through in a browser |
| 7c | Console tests, accessibility audit, screenshots | DONE (committed on v2-upgrade) | 2026-10-20 | default pytest 299 passed + 40 browser tests passed (pytest -m e2e tests/e2e), cov 89.72% (gate 82); ruff, ruff format --check, mypy, bandit, pip-audit (runtime and dev) clean; eval PASS F1=1.0; axe: 0 serious/critical on 8 screens, drawer and 2 dialogs, both themes; JS+CSS 90,944 bytes; 20 screenshots in docs/img | Browser job has not run on GitHub; tested with system Chrome locally, CI uses bundled Chromium; axe covers automatable WCAG 2.1 AA rules only (no screen-reader pass) |
| 8 | README and docs | DONE (committed on v2-upgrade) | 2026-10-20 | default pytest 318 passed (19 new docs tests), cov 89.84% (gate 82); ruff, ruff format --check, mypy (51 files), bandit, pip-audit (runtime and dev) clean; `gen_config_docs.py --check` current; eval PASS F1=1.0 | CI never ran on GitHub; browser tests not re-run this step (no UI change); D-number meanings recorded in CHANGELOG (D6, D8, D9, D14, D15 supplied by the owner) |
| Audit N1-N12 | Ingest-time retention (not in replay), read-only API + real /health, per-(IP, user) lockout, session/audit/triage housekeeping, app.db error wording, hygiene, docs honesty | DONE (committed on v2-upgrade) | 2026-10-20 | default pytest 341 passed + 40 browser tests passed, cov 90.01% (gate 82); ruff, ruff format --check, mypy (52 files), bandit, pip-audit (runtime and dev) clean; `gen_config_docs.py --check` current; eval PASS F1=1.0; README throughput 4,178-4,325 packets/sec over 3 runs | Read-only-volume behaviour tested with an OS-locked directory, not with Docker; live capture in a container and `NET_ADMIN` removal untested in CI; audit fixes are interleaved with the 6-7 code in the same files, so they landed in the first commit |

## Final checklist: everything still unverified locally

Run these yourself. Nothing below was run by the author unless stated.

1. **Full local gates**
   ```bash
   pytest --cov --cov-fail-under=82
   ruff check . && ruff format --check . && mypy
   bandit -c bandit.yaml -r backend capture config database detection eval logs ml scripts main.py
   pip-audit -r requirements.txt && pip-audit -r requirements-dev.txt
   python main.py eval --scenarios all --out eval_output
   python scripts/gen_config_docs.py --check
   ```
2. **Browser tests** (ran locally in step 7c with system Chrome; CI uses bundled Chromium): `pytest -m e2e tests/e2e`
3. **Docker (Linux), never run here**
   ```bash
   docker compose run --rm api python main.py user add admin --role admin
   docker compose up -d --build
   python scripts/ci_compose_check.py
   ```
4. **GitHub Actions: ran green on commit `cf2a691` (run 39465667959, all 12 jobs).** Re-check after any change by reading the jobs `api-fuzz` (Schemathesis + ZAP), `container-scan` (Trivy), `secret-scan` (gitleaks; may need a `GITLEAKS_LICENSE` secret for organisation repositories), `compose-integration` and `e2e`. Action versions were taken from their README pages, not from a run.
5. **Phase 5 data pipeline (needs the CIC-IDS2017 PCAPs in `D:\datasets\cicids2017\`, see `docs/DATASET.md`):**
   ```bash
   python scripts/build_flows.py D:\datasets\cicids2017\*.pcap --out flows.csv.gz
   SENTINELX_MODEL_KEY=<a long random secret> python main.py train --flows flows.csv.gz --out models
   SENTINELX_MODEL_KEY=<same secret> python main.py eval --pcap <held-out pcaps> --labels models/test_labels.json --ml-model models --out eval_output
   python scripts/gen_ml_report.py --train models/train_report.json --eval eval_output/ml_eval.json --meta flows.csv.gz.meta.json
   ```
   Until this passes its gate, ML stays off and no accuracy figure exists.
6. **Not testable by tooling:** screen-reader use of the console, behaviour with 10,000+ rows on a slow machine, the polling fallback on a real network, a real Npcap capture on Windows, a real Slack/Discord webhook.
7. **Refresh generated blocks after any change:** `python scripts/gen_config_docs.py` (config table) and `python scripts/gen_readme_results.py` (README results, after `eval`).
