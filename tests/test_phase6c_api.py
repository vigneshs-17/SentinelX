"""Step 6c: /api/v1 only, strict validation, rate limiting, headers, no CORS, SSE stream, trusted proxies."""

import json
import time

import pytest

import backend.api as api_mod
import backend.auth as auth_mod
import backend.ratelimit as rl
import main as main_mod
from backend import accounts
from backend.api import CSP, app
from backend.ratelimit import RateLimiter
from database.database import insert_alert, insert_sensor_status
from tests.support import authed_client


def seed(n=3, **kw):
    for i in range(n):
        insert_alert(
            {
                "timestamp": "2026-10-20T10:00:00+00:00",
                "detected_at": f"2026-10-20T10:00:{i:02d}+00:00",
                "threat_type": kw.get("threat_type", "PORT_SCAN"),
                "scan_type": kw.get("scan_type", "VERTICAL"),
                "severity": kw.get("severity", "HIGH"),
                "source_ip": kw.get("source_ip", f"10.0.{i}.5"),
                "destination_ip": "10.9.9.9",
                "protocol": "TCP",
                "message": "m",
            }
        )


@pytest.fixture
def viewer():
    return authed_client(app, "viewer")


# ------------------------------------------------------------------ versioning / envelope


def test_no_unversioned_aliases_remain(viewer):
    for url in ("/api/alerts", "/api/stats", "/api/health", "/logout", "/api/metrics"):
        assert viewer.get(url).status_code == 404, url
    assert viewer.post("/logout").status_code == 404


def test_every_api_route_lives_under_v1():
    allowed_outside = {"/", "/static/<path:filename>", "/health", "/login"}
    outside = {r.rule for r in app.url_map.iter_rules() if not r.rule.startswith("/api/v1/")} - allowed_outside
    assert not outside, outside


def test_single_json_error_envelope(viewer):
    anon = app.test_client()
    cases = [
        (anon.get("/api/v1/alerts"), 401),
        (viewer.get("/api/v1/users"), 403),
        (viewer.get("/nope"), 404),
        (viewer.delete("/api/v1/alerts"), 405),
        (viewer.get("/api/v1/alerts?limit=0"), 400),
        (viewer.post("/api/v1/alerts/1/triage", data="x" * 70_000, content_type="application/json"), 403),
    ]
    for resp, status in cases:
        body = resp.get_json()
        assert resp.status_code == status and set(body) == {"error", "message", "status"} and body["status"] == status
    analyst = authed_client(app, "analyst")
    big = analyst.post("/api/v1/alerts/1/triage", data="x" * 70_000, content_type="application/json")
    assert big.status_code == 413 and set(big.get_json()) == {"error", "message", "status"}


# ------------------------------------------------------------------ strict validation


def test_unknown_query_parameters_are_rejected_on_every_route(viewer):
    for url in ("/api/v1/alerts", "/api/v1/stats", "/api/v1/sensor/status", "/api/v1/session", "/api/v1/stream"):
        resp = viewer.get(f"{url}?bogus=1")
        assert resp.status_code == 400 and "bogus" in resp.get_json()["message"], url
    assert app.test_client().get("/health?x=1").status_code == 400
    admin = authed_client(app, "analyst")
    assert admin.get("/api/v1/alerts?limit=5&limit2=1").status_code == 400


def test_alert_filter_validation_and_cidr_filtering(viewer):
    seed(2, source_ip="10.0.0.5")
    seed(1, source_ip="192.168.1.9", threat_type="SYN_FLOOD", scan_type="SLOW", severity="LOW")
    q = lambda s: viewer.get(f"/api/v1/alerts?{s}")  # noqa: E731
    assert len(q("source_ip=10.0.0.5").get_json()) == 2
    assert len(q("source_ip=10.0.0.0/8").get_json()) == 2
    assert len(q("source_ip=192.168.1.0/24").get_json()) == 1
    assert q("source_ip=::1").get_json() == []
    assert len(q("scan_type=SLOW&severity=low").get_json()) == 1
    assert len(q("threat_type=HIGH_TRAFFIC").get_json()) == 0
    for bad in (
        "source_ip=not-an-ip",
        "source_ip=10.0.0.0/33",
        "scan_type=BOGUS",
        "limit=1.5",
        "offset=1000001",
        "since=2026-01-01T00:00:00",
        "since=nonsense",
        "severity=" + "A" * 80,
    ):
        assert q(bad).status_code == 400, bad
    assert q("since=2026-10-20T10:00:01%2B00:00&limit=1").status_code == 200


def test_session_and_metrics_routes_validate_nothing_else(viewer):
    assert viewer.get("/api/v1/session").status_code == 200
    assert viewer.get("/api/v1/sensor/status").status_code == 200


# ------------------------------------------------------------------ headers / CORS


def test_security_headers_on_success_and_error_responses(viewer):
    for resp in (
        viewer.get("/api/v1/stats"),
        app.test_client().get("/api/v1/stats"),
        viewer.get("/nope"),
        viewer.get("/"),
    ):
        h = resp.headers
        assert h["Content-Security-Policy"] == CSP
        assert h["X-Frame-Options"] == "DENY" and h["Referrer-Policy"] == "no-referrer"
        assert h["Cross-Origin-Opener-Policy"] == "same-origin" and h["Cross-Origin-Resource-Policy"] == "same-origin"
        assert h["X-Content-Type-Options"] == "nosniff"
        assert "X-XSS-Protection" not in h and "Strict-Transport-Security" not in h


def test_hsts_only_when_https_enabled(viewer, monkeypatch):
    monkeypatch.setattr(api_mod, "HTTPS_ENABLED", True)
    assert "max-age" in viewer.get("/api/v1/stats").headers["Strict-Transport-Security"]


def test_no_cors_headers_ever(viewer):
    for origin in ("http://127.0.0.1:5000", "http://localhost", "null", "https://evil.example"):
        for resp in (
            viewer.get("/api/v1/stats", headers={"Origin": origin}),
            viewer.options("/api/v1/stats", headers={"Origin": origin}),
        ):
            assert not [h for h in resp.headers.keys() if h.lower().startswith("access-control-")], origin


# ------------------------------------------------------------------ rate limiting


def test_rate_limit_headers_429_retry_after_and_refill(viewer, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(rl, "monotonic", lambda: now[0])
    monkeypatch.setattr(auth_mod, "API_RATE_LIMIT_PER_MIN", 5)
    first = viewer.get("/api/v1/stats")
    assert first.headers["RateLimit-Limit"] == "5" and first.headers["RateLimit-Remaining"] == "4"
    assert int(first.headers["RateLimit-Reset"]) >= 1
    for _ in range(4):
        assert viewer.get("/api/v1/stats").status_code == 200
    blocked = viewer.get("/api/v1/stats")
    assert blocked.status_code == 429 and blocked.headers["Retry-After"] == "12"
    assert blocked.headers["RateLimit-Remaining"] == "0" and blocked.get_json()["status"] == 429
    now[0] += 12.5  # 5/min refills one token every 12 s
    assert viewer.get("/api/v1/stats").status_code == 200
    assert viewer.get("/api/v1/stats").status_code == 429


def test_rate_limit_is_per_identity_and_ip_for_anonymous(monkeypatch):
    monkeypatch.setattr(rl, "monotonic", lambda: 50.0)
    monkeypatch.setattr(auth_mod, "API_RATE_LIMIT_PER_MIN", 3)
    a, b = authed_client(app, "viewer"), authed_client(app, "viewer")
    for _ in range(3):
        assert a.get("/api/v1/stats").status_code == 200
    assert a.get("/api/v1/stats").status_code == 429
    assert b.get("/api/v1/stats").status_code == 200  # another key has its own bucket
    anon = app.test_client()
    for _ in range(3):
        assert anon.get("/api/v1/stats", environ_overrides={"REMOTE_ADDR": "198.51.100.1"}).status_code == 401
    assert anon.get("/api/v1/stats", environ_overrides={"REMOTE_ADDR": "198.51.100.1"}).status_code == 429
    assert anon.get("/api/v1/stats", environ_overrides={"REMOTE_ADDR": "198.51.100.2"}).status_code == 401


def test_login_has_a_stricter_per_ip_limit_and_health_is_exempt(monkeypatch):
    accounts.create_user("rate-user", "a long enough password", "viewer")
    monkeypatch.setattr(rl, "monotonic", lambda: 7.0)
    monkeypatch.setattr(auth_mod, "LOGIN_RATE_LIMIT_PER_MIN", 3)
    c = app.test_client()
    codes = [
        c.post("/login", json={"username": "rate-user", "password": "a long enough password"}).status_code
        for _ in range(5)
    ]
    assert codes == [200, 200, 200, 429, 429]
    limited = c.post("/login", json={"username": "x", "password": "y"})
    assert limited.headers["Retry-After"] and limited.headers["RateLimit-Limit"] == "3"
    for _ in range(30):
        assert c.get("/health").status_code == 200 and c.get("/static/css/app.css").status_code == 200
    assert "RateLimit-Limit" not in c.get("/health").headers


def test_rate_limiter_memory_is_bounded(monkeypatch):
    monkeypatch.setattr(rl, "monotonic", lambda: 1.0)
    limiter = RateLimiter(max_buckets=50)
    for i in range(2000):
        limiter.check(f"ip:10.1.{i // 250}.{i % 250}", 10)
    assert limiter.size() == 50


# ------------------------------------------------------------------ trusted proxies


def _ip(headers, remote):
    with app.test_request_context("/", headers=headers, environ_base={"REMOTE_ADDR": remote}):
        return auth_mod.client_ip()


def test_forwarded_for_is_ignored_unless_the_peer_is_a_trusted_proxy(monkeypatch):
    xff = {"X-Forwarded-For": "6.6.6.6, 203.0.113.9"}
    assert _ip(xff, "10.0.0.1") == "10.0.0.1"  # no trusted proxies configured
    monkeypatch.setattr(auth_mod, "TRUSTED_PROXIES", ["10.0.0.0/8"])
    assert _ip(xff, "198.51.100.5") == "198.51.100.5"  # peer not trusted: header is attacker-controlled
    assert _ip(xff, "10.0.0.1") == "203.0.113.9"  # right-most untrusted hop
    assert _ip({"X-Forwarded-For": "6.6.6.6, 10.0.0.7"}, "10.0.0.1") == "6.6.6.6"  # trusted hops skipped
    assert _ip({"X-Forwarded-For": "garbage"}, "10.0.0.1") == "10.0.0.1"
    assert _ip({}, "10.0.0.1") == "10.0.0.1"


# ------------------------------------------------------------------ SSE stream


@pytest.fixture
def fast_stream(monkeypatch):
    monkeypatch.setattr(api_mod, "STREAM_INTERVAL_SECONDS", 0.05)
    monkeypatch.setattr(api_mod, "STREAM_HEARTBEAT_SECONDS", 0.05)


def events(resp, n):
    out = []
    it = iter(resp.response)
    while len(out) < n:
        chunk = next(it)
        out.append(chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk)
    return out


def test_stream_requires_auth_and_validates_after_id(viewer):
    assert app.test_client().get("/api/v1/stream").status_code == 401
    assert viewer.get("/api/v1/stream?after_id=-1").status_code == 400
    assert viewer.get("/api/v1/stream?after_id=abc").status_code == 400
    assert api_mod.open_stream_count() == 0


def test_stream_pushes_new_alert_ids_and_metrics(viewer, fast_stream):
    seed(1)
    insert_sensor_status(
        {
            "sensor_id": "s",
            "last_seen": api_mod.utcnow().isoformat(timespec="seconds"),
            "received": 1,
            "dropped": 0,
            "queue_depth": 0,
            "pps_10s": 1.0,
            "state_size": 1,
            "evictions": 0,
            "webhook_failures": 0,
        }
    )
    resp = viewer.get("/api/v1/stream")
    assert (
        resp.status_code == 200 and resp.mimetype == "text/event-stream" and resp.headers["Cache-Control"] == "no-store"
    )
    try:
        first = events(resp, 1)[0]
        assert first.startswith("retry: 5000") and "event: update" in first
        payload = json.loads(first.split("data: ", 1)[1])
        assert payload["new_alert_ids"] == [] and payload["metrics"]["sensor_online"] is True
        seed(1, source_ip="10.77.0.1")
        deadline = time.time() + 5
        got = []
        while not got and time.time() < deadline:
            chunk = events(resp, 1)[0]
            if chunk.startswith("event: update"):
                got = json.loads(chunk.split("data: ", 1)[1])["new_alert_ids"]
        assert len(got) == 1
    finally:
        resp.close()
    assert api_mod.open_stream_count() == 0


def test_stream_after_id_replays_newer_alerts(viewer, fast_stream):
    seed(3)
    resp = viewer.get("/api/v1/stream?after_id=0")
    try:
        data = json.loads(events(resp, 1)[0].split("data: ", 1)[1])
        assert len(data["new_alert_ids"]) == 3 and data["latest_alert_id"] == data["new_alert_ids"][-1]
    finally:
        resp.close()


def test_stream_heartbeat_when_idle(viewer, monkeypatch):
    monkeypatch.setattr(api_mod, "STREAM_INTERVAL_SECONDS", 30.0)
    monkeypatch.setattr(api_mod, "STREAM_HEARTBEAT_SECONDS", 0.05)
    resp = viewer.get("/api/v1/stream")
    try:
        events(resp, 1)  # initial snapshot
        assert events(resp, 1)[0] == ": heartbeat\n\n"
    finally:
        resp.close()


def test_stream_cap_is_enforced_and_slots_are_released(viewer, fast_stream, monkeypatch):
    monkeypatch.setattr(api_mod, "MAX_STREAMS", 2)
    a, b = viewer.get("/api/v1/stream"), viewer.get("/api/v1/stream")
    assert a.status_code == b.status_code == 200 and api_mod.open_stream_count() == 2
    refused = viewer.get("/api/v1/stream")
    assert (
        refused.status_code == 429
        and refused.headers["Retry-After"] == "5"
        and "polling" in refused.get_json()["message"]
    )
    a.close()
    a.close()  # idempotent: must not double-release
    assert api_mod.open_stream_count() == 1
    c = viewer.get("/api/v1/stream")
    assert c.status_code == 200 and api_mod.open_stream_count() == 2
    b.close()
    c.close()
    assert api_mod.open_stream_count() == 0


def test_api_command_requires_thread_headroom_for_streams(monkeypatch, capsys):
    import config.settings as settings

    monkeypatch.setattr(main_mod, "API_THREADS", 8)
    monkeypatch.setattr(settings, "MAX_STREAMS", 8)
    with pytest.raises(SystemExit) as exc:
        main_mod.handle_api(main_mod.parse_arguments(["api"]))
    assert exc.value.code == 2 and "headroom" in capsys.readouterr().out


# ------------------------------------------------------------------ regressions found by Schemathesis


def test_oversized_ids_are_404_not_500():
    """Found by Schemathesis: ids above SQLite's INTEGER range raised OverflowError (HTTP 500)."""
    admin = authed_client(app, "analyst")
    huge = 2**63
    assert admin.get(f"/api/v1/alerts/{huge}/triage").status_code == 404
    assert admin.post(f"/api/v1/alerts/{huge}/triage", json={"status": "new"}).status_code == 404
    accounts.create_user("adm-huge", "a long enough password", "admin")
    from tests.test_phase6b_auth import do_login

    c, resp = do_login("adm-huge", "a long enough password")
    csrf = resp.get_json()["csrf_token"]
    for path in (f"/api/v1/users/{huge}/disable", f"/api/v1/users/{huge}/revoke-sessions"):
        assert c.post(path, headers={"X-CSRF-Token": csrf}).status_code == 404
    assert c.delete(f"/api/v1/apikeys/{huge}", headers={"X-CSRF-Token": csrf}).status_code == 404


def test_405_carries_the_allow_header(viewer):
    resp = viewer.delete("/api/v1/stats")
    assert resp.status_code == 405 and "GET" in resp.headers["Allow"]
    assert resp.get_json()["status"] == 405
