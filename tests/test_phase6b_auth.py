"""Step 6b: authentication, sessions, CSRF, API keys, login protection, authorization matrix, triage, audit log."""

import hashlib
import json
import logging
import sqlite3

import pytest
from argon2 import PasswordHasher
from flask import Flask

import main as main_mod
from backend import accounts, auth, passwords
from backend import api as api_mod
from backend.auth import SESSION_COOKIE, init_auth
from database.app_db import get_app_connection
from database.database import get_connection, insert_alert
from tests.support import authed_client

app = api_mod.app
T0 = 1_800_000_000.0

PW = {"admin": "admin horse battery", "analyst": "analyst horse battery", "viewer": "viewer horse battery"}


class Clock:
    def __init__(self):
        self.t = T0

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(accounts, "now", lambda: c.t)
    return c


@pytest.fixture
def users(clock):
    for role in ("admin", "analyst", "viewer"):
        accounts.create_user(f"{role}-user", PW[role], role)
    return {role: f"{role}-user" for role in PW}


@pytest.fixture
def alert_id():
    insert_alert(
        {
            "timestamp": "2026-10-20T10:00:00+00:00",
            "detected_at": "2026-10-20T10:00:00+00:00",
            "threat_type": "PORT_SCAN",
            "severity": "HIGH",
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.9",
            "protocol": "TCP",
            "message": "m",
        }
    )
    conn = get_connection()
    try:
        return conn.execute("SELECT MAX(id) FROM alerts").fetchone()[0]
    finally:
        conn.close()


def alerts_count():
    conn = get_connection()
    try:
        return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    finally:
        conn.close()


def do_login(role_or_name, password=None, ip="203.0.113.7", client=None):
    name = f"{role_or_name}-user" if role_or_name in PW else role_or_name
    pw = password if password is not None else PW.get(role_or_name, "")
    c = client or app.test_client()
    resp = c.post("/login", json={"username": name, "password": pw}, environ_overrides={"REMOTE_ADDR": ip})
    return c, resp


def session_client(role, **kw):
    c, resp = do_login(role, **kw)
    assert resp.status_code == 200, resp.get_json()
    return c, resp.get_json()["csrf_token"]


def post(c, csrf, url, **kw):
    headers = {"X-CSRF-Token": csrf} if csrf else {}
    return c.post(url, headers=headers, **kw)


def appexec(sql, params=()):
    conn = get_app_connection()
    try:
        with conn:
            conn.execute(sql, params)
    finally:
        conn.close()


def appdb(sql, params=()):
    conn = get_app_connection()
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


# ------------------------------------------------------------------ passwords


def test_password_policy_and_argon2id():
    assert passwords.validate_password("short") and passwords.validate_password("a" * 11)
    assert passwords.validate_password("a" * 12 + "b") is None
    assert passwords.validate_password("PassWord1234") == "That password is too common."
    assert "common" in passwords.validate_password("qwertyuiop123")
    assert "username" in passwords.validate_password("samenamesamename", "SameNameSameName")
    h = passwords.hash_password("correct horse battery")
    assert h.startswith("$argon2id$")
    assert passwords.verify_password(h, "correct horse battery") and not passwords.verify_password(h, "nope")
    assert passwords.verify_password(None, "anything") is False  # dummy-hash path never succeeds


def test_create_user_rules(clock):
    with pytest.raises(accounts.AccountError, match="at least"):
        accounts.create_user("bob_x", "short", "viewer")
    with pytest.raises(accounts.AccountError, match="Username"):
        accounts.create_user("a b", "long enough password", "viewer")
    with pytest.raises(accounts.AccountError, match="Role"):
        accounts.create_user("bobby", "long enough password", "root")
    accounts.create_user("bobby", "long enough password", "viewer")
    with pytest.raises(accounts.AccountError, match="exists"):
        accounts.create_user("BOBBY", "another long password", "viewer")


def test_login_rehashes_when_parameters_change(users):
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PW["viewer"])
    appexec("UPDATE users SET password_hash = ? WHERE username = ?", (weak, users["viewer"]))
    assert passwords.needs_rehash(weak)
    _, resp = do_login("viewer")
    assert resp.status_code == 200
    stored = accounts.get_user_by_name(users["viewer"])["password_hash"]
    assert stored != weak and not passwords.needs_rehash(stored)
    assert passwords.verify_password(stored, PW["viewer"])


# ------------------------------------------------------------------ login behaviour


def test_login_error_is_generic_and_unknown_users_pay_for_a_verification(users, monkeypatch):
    calls = []
    real = passwords._hasher

    class Spy:
        def verify(self, h, pw):
            calls.append(h)
            return real.verify(h, pw)

        def __getattr__(self, name):
            return getattr(real, name)

    monkeypatch.setattr(passwords, "_hasher", Spy())
    _, wrong_pw = do_login("viewer", "totally wrong password")
    n_known = len(calls)
    _, no_user = do_login("ghost-user", "totally wrong password")
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.get_json() == no_user.get_json()
    assert wrong_pw.get_json()["message"] == "Invalid username or password."
    assert n_known == 1 and len(calls) == 2 and calls[1] == passwords.dummy_hash()  # dummy hash verified once


def test_login_input_validation(users):
    c = app.test_client()
    for body in (None, {}, {"username": "x"}, {"username": 5, "password": "x"}, {"username": "", "password": "x"}, [1]):
        assert c.post("/login", json=body).status_code == 400
    assert c.post("/login", data="notjson", content_type="text/plain").status_code == 400


def test_session_cookie_flags_and_server_side_hashed_storage(users, monkeypatch):
    c, resp = do_login("analyst")
    cookie = resp.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie and "Secure" not in cookie
    token = c.get_cookie(SESSION_COOKIE).value
    assert len(token) >= 43  # 256 bits, url-safe base64
    rows = appdb("SELECT token_hash FROM sessions")
    assert [r[0] for r in rows] == [hashlib.sha256(token.encode()).hexdigest()]
    assert token not in json.dumps([tuple(r) for r in appdb("SELECT * FROM sessions")])
    monkeypatch.setattr(auth, "HTTPS_ENABLED", True)
    assert "Secure" in do_login("viewer")[1].headers["Set-Cookie"]


def test_new_session_id_on_every_login_and_no_fixation(users):
    c, first = do_login("viewer")
    t1 = c.get_cookie(SESSION_COOKIE).value
    _, second = do_login("viewer", client=c)
    t2 = c.get_cookie(SESSION_COOKIE).value
    assert t1 != t2 and first.get_json()["csrf_token"] != second.get_json()["csrf_token"]
    c.set_cookie(SESSION_COOKIE, t1)  # old token is dead: it was replaced, not reused
    assert c.get("/api/v1/stats").status_code == 401

    attacker = app.test_client()
    attacker.set_cookie(SESSION_COOKIE, "attacker-chosen-token-0123456789")
    _, resp = do_login("viewer", client=attacker)
    assert resp.status_code == 200 and attacker.get_cookie(SESSION_COOKIE).value != "attacker-chosen-token-0123456789"


def test_logout_deletes_the_server_side_session(users):
    c, csrf = session_client("viewer")
    token = c.get_cookie(SESSION_COOKIE).value
    assert post(c, csrf, "/api/v1/logout").status_code == 204
    assert appdb("SELECT COUNT(*) FROM sessions")[0][0] == 0
    c.set_cookie(SESSION_COOKIE, token)
    assert c.get("/api/v1/stats").status_code == 401


def test_idle_and_absolute_session_timeouts(users, clock):
    c, _ = session_client("viewer")
    clock.advance(1700)
    assert c.get("/api/v1/stats").status_code == 200  # activity refreshes the idle timer
    clock.advance(1801)
    assert c.get("/api/v1/stats").status_code == 401  # idle > 30 min
    assert appdb("SELECT COUNT(*) FROM sessions")[0][0] == 0

    c2, _ = session_client("viewer")
    start = clock.t
    status = 200
    while status == 200 and clock.t - start < 13 * 3600:
        clock.advance(1500)  # always inside the 30 min idle window, so only the 12 h absolute limit can end it
        status = c2.get("/api/v1/stats").status_code
    assert status == 401 and 12 * 3600 < clock.t - start <= 12 * 3600 + 1500


def test_disabled_user_loses_login_and_existing_sessions(users):
    c, _ = session_client("viewer")
    accounts.set_disabled(users["viewer"], True)
    assert c.get("/api/v1/stats").status_code == 401
    assert do_login("viewer")[1].status_code == 401
    accounts.set_disabled(users["viewer"], False)
    assert do_login("viewer")[1].status_code == 200


def test_cannot_disable_last_admin(users):
    with pytest.raises(accounts.AccountError, match="last enabled admin"):
        accounts.set_disabled(users["admin"], True)


# ------------------------------------------------------------------ CSRF / Origin


def test_csrf_token_and_origin_checks_for_cookie_sessions(users, alert_id):
    c, csrf = session_client("analyst")
    url = f"/api/v1/alerts/{alert_id}/triage"
    body = {"status": "acknowledged"}
    assert c.post(url, json=body).status_code == 403
    assert c.post(url, json=body, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert c.post(url, json=body, headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"}).status_code == 403
    assert c.post(url, json=body, headers={"X-CSRF-Token": csrf, "Origin": "null"}).status_code == 403
    assert c.post(url, json=body, headers={"X-CSRF-Token": csrf, "Origin": "http://localhost"}).status_code == 200
    assert c.post(url, json=body, headers={"X-CSRF-Token": csrf}).status_code == 200
    assert c.get(url).status_code == 200  # safe methods need no token


def test_login_post_rejects_foreign_origin(users):
    c = app.test_client()
    resp = c.post(
        "/login",
        json={"username": users["viewer"], "password": PW["viewer"]},
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code == 403


def test_bearer_requests_ignore_cookies_and_need_no_csrf(users, alert_id):
    c, _ = session_client("viewer")  # valid cookie present
    c.environ_base["HTTP_AUTHORIZATION"] = "Bearer sx_not-a-real-key"
    assert c.get("/api/v1/stats").status_code == 401  # no fallback to the cookie
    analyst = authed_client(app, "analyst")
    assert analyst.post(f"/api/v1/alerts/{alert_id}/triage", json={"status": "resolved_fp"}).status_code == 200


# ------------------------------------------------------------------ login protection


def attempts(n, username="viewer-user", pw="bad password here", ip="198.51.100.9"):
    return [do_login(username, pw, ip)[1] for _ in range(n)]


def test_lockout_after_five_failures_with_exponential_delay_and_retry_after(users, clock):
    for r in attempts(5):
        assert r.status_code == 401
    locked = do_login("viewer", PW["viewer"], "198.51.100.9")[1]  # even the right password is refused while locked
    assert locked.status_code == 429 and int(locked.headers["Retry-After"]) in range(29, 32)
    assert "Try again in" in locked.get_json()["message"]
    clock.advance(31)
    assert attempts(1)[0].status_code == 401  # 6th failure: next lock is 60 s
    clock.advance(31)
    assert do_login("viewer", PW["viewer"], "198.51.100.9")[1].status_code == 429
    clock.advance(30)
    assert do_login("viewer", PW["viewer"], "198.51.100.9")[1].status_code == 200
    clock.advance(16 * 60)
    assert (
        do_login("viewer", "bad password here", "198.51.100.9")[1].status_code == 401
    )  # window expired, counters reset


def test_lockout_is_per_ip_username_pair_and_per_ip_and_does_not_reveal_user_existence(users):
    for _ in range(5):  # N3: failures from IP A lock only the (A, viewer) pair
        do_login("viewer", "bad password here", "192.0.2.1")
    assert do_login("viewer", PW["viewer"], "192.0.2.1")[1].status_code == 429
    assert do_login("viewer", PW["viewer"], "192.0.2.99")[1].status_code == 200  # IP B is not blocked
    assert do_login("analyst", PW["analyst"], "192.0.2.1")[1].status_code == 200  # other user from A is fine
    limit = 5 * auth.LoginThrottle.IP_FAILURE_FACTOR
    for i in range(limit):  # one IP guessing across many usernames hits the per-IP counter
        do_login(f"nobody-{i}", "bad password here", "192.0.2.50")
    assert do_login("admin", PW["admin"], "192.0.2.50")[1].status_code == 429
    assert do_login("admin", PW["admin"], "192.0.2.51")[1].status_code == 200
    ghost = [do_login("ghost-name", "bad password here", "192.0.2.100")[1] for _ in range(6)]
    real = [do_login("analyst", "bad password here", "192.0.2.120")[1] for _ in range(6)]
    assert ghost[-1].status_code == real[-1].status_code == 429  # unknown and known names lock identically
    assert [r.get_json()["error"] for r in ghost] == [r.get_json()["error"] for r in real]
    assert [r.get_json()["message"] for r in ghost[:5]] == [r.get_json()["message"] for r in real[:5]]


def test_failures_counted_in_metrics_and_audit_log(users):
    before = auth.auth_metrics["login_failures"]
    attempts(2)
    assert auth.auth_metrics["login_failures"] == before + 2
    rows = [r for r in accounts.query_audit(action="login.failure")]
    assert len(rows) == 2 and rows[0]["target"] == "user:viewer-user" and rows[0]["source_ip"] == "198.51.100.9"
    body = authed_client(app).get("/api/v1/sensor/status").get_json()
    assert body["api"]["login_failures"] >= before + 2


# ------------------------------------------------------------------ API keys


def test_api_key_lifecycle_hash_only_prefix_last_used_and_immediate_revocation(users, clock, capsys):
    main_mod.handle_apikey(main_mod.parse_arguments(["apikey", "create", "--role", "viewer", "--name", "siem"]))
    printed = capsys.readouterr().out.strip().splitlines()
    raw = printed[-1]
    assert raw.startswith("sx_") and len(raw) > 40
    dump = json.dumps([tuple(r) for r in appdb("SELECT * FROM api_keys")]) + json.dumps(
        [tuple(r) for r in appdb("SELECT * FROM audit_log")]
    )
    assert raw not in dump and hashlib.sha256(raw.encode()).hexdigest() in dump

    c = app.test_client()
    c.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {raw}"
    assert c.get("/api/v1/stats").status_code == 200
    assert accounts.list_api_keys()[0]["last_used_at"] == T0
    main_mod.handle_apikey(main_mod.parse_arguments(["apikey", "list"]))
    listing = capsys.readouterr().out
    assert raw[:8] in listing and raw not in listing

    key_id = accounts.list_api_keys()[0]["id"]
    main_mod.handle_apikey(main_mod.parse_arguments(["apikey", "revoke", str(key_id)]))
    assert c.get("/api/v1/stats").status_code == 401  # very next request
    with pytest.raises(SystemExit):
        main_mod.handle_apikey(main_mod.parse_arguments(["apikey", "revoke", str(key_id)]))


def test_api_key_roles_are_limited_to_viewer_and_analyst():
    with pytest.raises(accounts.AccountError):
        accounts.create_api_key("x", "admin")
    with pytest.raises(SystemExit):
        main_mod.parse_arguments(["apikey", "create", "--role", "admin", "--name", "x"])


# ------------------------------------------------------------------ authorization


def test_every_route_has_an_explicit_policy():
    missing = [
        r.rule for r in app.url_map.iter_rules() if getattr(app.view_functions[r.endpoint], "_sx_policy", None) is None
    ]
    assert not missing, f"routes without an access policy: {missing}"
    public_rules = {r.rule for r in app.url_map.iter_rules() if app.view_functions[r.endpoint]._sx_policy == "public"}
    assert public_rules == {"/", "/static/<path:filename>", "/health", "/login"}


def test_unpoliced_view_is_denied_by_default():
    mini = Flask(__name__)
    init_auth(mini)

    @mini.route("/oops")
    def oops():
        return "should never be served"

    resp = mini.test_client().get("/oops")
    assert resp.status_code == 403 and b"never be served" not in resp.data


# (method, url, minimum role that may call it)
PROTECTED = [
    ("GET", "/api/v1/alerts", "viewer"),
    ("GET", "/api/v1/stats", "viewer"),
    ("GET", "/api/v1/sensor/status", "viewer"),
    ("GET", "/api/v1/session", "viewer"),
    ("GET", "/api/v1/stream", "viewer"),
    ("GET", "/api/v1/overview", "viewer"),
    ("GET", "/api/v1/graph", "viewer"),
    ("GET", "/api/v1/sensor/history", "viewer"),
    ("GET", "/api/v1/alerts/export", "viewer"),
    ("GET", "/api/v1/assignees", "analyst"),
    ("GET", "/api/v1/alerts/1/triage", "viewer"),
    ("POST", "/api/v1/alerts/1/triage", "analyst"),
    ("GET", "/api/v1/users", "admin"),
    ("POST", "/api/v1/users", "admin"),
    ("POST", "/api/v1/users/999/disable", "admin"),
    ("POST", "/api/v1/users/999/enable", "admin"),
    ("POST", "/api/v1/users/999/reset-password", "admin"),
    ("POST", "/api/v1/users/999/revoke-sessions", "admin"),
    ("GET", "/api/v1/apikeys", "admin"),
    ("POST", "/api/v1/apikeys", "admin"),
    ("DELETE", "/api/v1/apikeys/999", "admin"),
    ("GET", "/api/v1/audit", "admin"),
    ("POST", "/api/v1/logout", "viewer"),  # last: it ends the caller's session
]
RANK = {"viewer": 0, "analyst": 1, "admin": 2}


def _concrete(rule: str) -> str:
    import re

    return re.sub(r"<[^>]+>", "1", rule)


def test_matrix_covers_every_non_public_route():
    in_app = {
        (m, _concrete(r.rule).replace("/1/", "/1/"))
        for r in app.url_map.iter_rules()
        for m in r.methods - {"HEAD", "OPTIONS"}
        if app.view_functions[r.endpoint]._sx_policy != "public"
    }
    in_matrix = {(m, u.replace("/999/", "/1/").replace("/999", "/1")) for m, u, _ in PROTECTED}
    assert in_app == in_matrix


def call(client, method, url, csrf=None):
    headers = {"X-CSRF-Token": csrf} if csrf else {}
    body = (
        {"status": "new"} if "triage" in url else ({"name": "k", "role": "viewer"} if url.endswith("apikeys") else {})
    )
    resp = client.open(url, method=method, headers=headers, json=body if method == "POST" else None)
    resp.close()  # releases an SSE stream slot if this opened one
    return resp


def test_full_authorization_matrix(users, alert_id, clock):
    principals = {}
    for role in PW:
        principals[role] = session_client(role)
    principals["key-viewer"] = (authed_client(app, "viewer"), None)
    principals["key-analyst"] = (authed_client(app, "analyst"), None)
    revoked = authed_client(app, "analyst")
    key_id = accounts.list_api_keys()[-1]["id"]
    accounts.revoke_api_key(key_id)
    principals["revoked-key"] = (revoked, None)
    expired, expired_csrf = session_client("admin", ip="203.0.113.77")
    clock.advance(31 * 60)
    principals["expired-session"] = (expired, expired_csrf)
    principals["anonymous"] = (app.test_client(), None)
    # sessions created before the clock jump are idle-expired too; log the live ones in again
    for role in PW:
        principals[role] = session_client(role, ip=f"203.0.113.{RANK[role] + 1}")

    effective = {
        "admin": "admin",
        "analyst": "analyst",
        "viewer": "viewer",
        "key-viewer": "viewer",
        "key-analyst": "analyst",
    }
    for method, url, minimum in PROTECTED:
        for name, (client, csrf) in principals.items():
            status = call(client, method, url, csrf).status_code  # 999 = no such user/key: 404 after auth passes
            if name in effective:
                if RANK[effective[name]] >= RANK[minimum]:
                    assert status not in (401, 403), (name, method, url, status)
                else:
                    assert status == 403, (name, method, url, status)
            else:
                assert status == 401, (name, method, url, status)


def test_public_routes_need_no_credentials():
    c = app.test_client()
    assert (
        c.get("/").status_code == 200
        and c.get("/health").status_code == 200
        and c.get("/static/css/app.css").status_code == 200
    )


def test_unknown_url_is_404_not_a_policy_error():
    assert app.test_client().get("/nope").status_code == 404


# ------------------------------------------------------------------ triage + audit


def test_triage_validation_persistence_and_alerts_db_untouched(users, alert_id):
    c = authed_client(app, "analyst")
    url = f"/api/v1/alerts/{alert_id}/triage"
    bad = [
        {},
        {"status": "closed"},
        {"status": "new", "extra": 1},
        {"status": "new", "note": "x" * 2001},
        {"status": "new", "note": "bad\x00char"},
        {"status": "new", "note": 5},
        {"status": "new", "assignee": "nobody-here"},
        {"status": "new", "assignee": "bad name!"},
        {"status": "new", "assignee": 7},
    ]
    for body in bad:
        assert c.post(url, json=body).status_code == 400, body
    assert c.post(url, data="x", content_type="text/plain").status_code == 400
    assert c.post("/api/v1/alerts/987654/triage", json={"status": "new"}).status_code == 404

    before = alerts_count()
    ok = c.post(url, json={"status": "investigating", "assignee": users["viewer"], "note": "line1\nline2 <b>plain</b>"})
    assert ok.status_code == 200 and ok.get_json()["status"] == "investigating"
    c.post(url, json={"status": "resolved_tp"})
    state = c.get(url).get_json()
    assert state["triage"]["status"] == "resolved_tp" and len(state["history"]) == 2
    assert (
        state["history"][1]["detail"]["to"] == "investigating"
        and state["history"][0]["detail"]["from"] == "investigating"
    )
    assert alerts_count() == before


def test_audit_log_is_append_only_admin_only_and_records_every_category(users, alert_id):
    admin, csrf = session_client("admin")
    post(
        admin,
        csrf,
        "/api/v1/users",
        json={"username": "new-user", "password": "a long enough password", "role": "viewer"},
    )
    post(admin, csrf, "/api/v1/apikeys", json={"name": "k1", "role": "viewer"})
    analyst, acsrf = session_client("analyst")
    post(analyst, acsrf, f"/api/v1/alerts/{alert_id}/triage", json={"status": "acknowledged"})
    post(analyst, acsrf, "/api/v1/logout")
    do_login("viewer", "wrong wrong wrong")

    actions = {r["action"] for r in admin.get("/api/v1/audit?limit=500").get_json()}
    assert {"login.success", "login.failure", "logout", "user.create", "apikey.create", "triage.update"} <= actions
    row = admin.get("/api/v1/audit?action=triage.update").get_json()[0]
    assert row["actor"] == "user:analyst-user" and row["target"] == f"alert:{alert_id}" and row["ts"].endswith("+00:00")
    assert row["source_ip"] == "127.0.0.1"  # the request address (test client default)

    assert authed_client(app, "analyst").get("/api/v1/audit").status_code == 403
    assert admin.get("/api/v1/audit?bogus=1").status_code == 400
    assert admin.get("/api/v1/audit?limit=0").status_code == 400
    assert admin.get("/api/v1/audit?since=2026-01-01T00:00:00").status_code == 400

    conn = get_app_connection()
    for stmt in ("UPDATE audit_log SET actor='x'", "DELETE FROM audit_log"):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(stmt)
    conn.close()
    with pytest.raises(ValueError, match="secret"):
        accounts.audit("x", "cli", detail={"password": "p"})


def test_no_secret_ever_reaches_logs_audit_table_or_api_responses(users, alert_id, caplog):
    secrets_ = {
        "password": "S3cret passphrase Alpha",
        "new_password": "S3cret passphrase Beta!",
        "webhook": "https://hooks.example.com/services/XYZ-SECRET",
    }
    with caplog.at_level(logging.DEBUG):
        c, resp = do_login("admin")
        csrf = resp.get_json()["csrf_token"]
        token = c.get_cookie(SESSION_COOKIE).value
        post(
            c, csrf, "/api/v1/users", json={"username": "temp-user", "password": secrets_["password"], "role": "viewer"}
        )
        uid = accounts.get_user_by_name("temp-user")["id"]
        post(c, csrf, f"/api/v1/users/{uid}/reset-password", json={"password": secrets_["new_password"]})
        _, key_resp = (None, post(c, csrf, "/api/v1/apikeys", json={"name": "k", "role": "analyst"}))
        raw_key = key_resp.get_json()["key"]
        do_login("temp-user", secrets_["password"])  # stale password now fails
        authed = app.test_client()
        authed.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {raw_key}"
        authed.post(f"/api/v1/alerts/{alert_id}/triage", json={"status": "new", "note": "ok"})
        listing = [
            c.get("/api/v1/audit?limit=500").get_data(as_text=True),
            c.get("/api/v1/apikeys").get_data(as_text=True),
            c.get("/api/v1/users").get_data(as_text=True),
        ]
    haystack = caplog.text + json.dumps([tuple(r) for r in appdb("SELECT * FROM audit_log")]) + "".join(listing)
    for secret in (*secrets_.values(), token, csrf, raw_key, PW["admin"]):
        assert secret not in haystack, f"secret leaked: {secret[:6]}..."
    assert "password_hash" not in "".join(listing) and "$argon2" not in "".join(listing)


# ------------------------------------------------------------------ admin API and CLI


def test_admin_api_user_management(users):
    admin, csrf = session_client("admin")
    ok = post(
        admin,
        csrf,
        "/api/v1/users",
        json={"username": "carol-x", "password": "a long enough password", "role": "analyst"},
    )
    assert ok.status_code == 201
    uid = ok.get_json()["id"]
    assert (
        post(
            admin,
            csrf,
            "/api/v1/users",
            json={"username": "carol-x", "password": "a long enough password", "role": "analyst"},
        ).status_code
        == 400
    )
    assert (
        post(
            admin, csrf, "/api/v1/users", json={"username": "dave-x", "password": "short", "role": "viewer"}
        ).status_code
        == 400
    )
    assert (
        post(
            admin,
            csrf,
            "/api/v1/users",
            json={"username": "dave-x", "password": "a long enough password", "role": "viewer", "x": 1},
        ).status_code
        == 400
    )

    carol, _ = session_client("carol-x", password="a long enough password", ip="203.0.113.50")
    assert post(admin, csrf, f"/api/v1/users/{uid}/revoke-sessions").get_json() == {"revoked": 1}
    assert carol.get("/api/v1/stats").status_code == 401
    assert (
        post(
            admin, csrf, f"/api/v1/users/{uid}/reset-password", json={"password": "brand new long password"}
        ).status_code
        == 204
    )
    assert do_login("carol-x", "a long enough password", "203.0.113.51")[1].status_code == 401
    assert do_login("carol-x", "brand new long password", "203.0.113.52")[1].status_code == 200
    assert post(admin, csrf, f"/api/v1/users/{uid}/disable").status_code == 204
    assert post(admin, csrf, f"/api/v1/users/{uid}/enable").status_code == 204
    assert post(admin, csrf, "/api/v1/users/9999/disable").status_code == 404
    names = [u["username"] for u in admin.get("/api/v1/users").get_json()]
    assert "carol-x" in names and all("password_hash" not in u for u in admin.get("/api/v1/users").get_json())


def test_admin_api_keys_create_list_revoke(users):
    admin, csrf = session_client("admin")
    created = post(admin, csrf, "/api/v1/apikeys", json={"name": "ci", "role": "analyst"}).get_json()
    assert created["key"].startswith("sx_")
    listing = admin.get("/api/v1/apikeys").get_json()
    assert listing[0]["prefix"] == created["key"][:8] and "key" not in listing[0] and "key_hash" not in listing[0]
    assert post(admin, csrf, "/api/v1/apikeys", json={"name": "bad", "role": "admin"}).status_code == 400
    assert admin.delete(f"/api/v1/apikeys/{created['id']}", headers={"X-CSRF-Token": csrf}).status_code == 204
    assert admin.delete(f"/api/v1/apikeys/{created['id']}", headers={"X-CSRF-Token": csrf}).status_code == 404


def test_cli_user_commands(users, monkeypatch, capsys):
    answers = iter(["cli user long password", "cli user long password"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    main_mod.handle_user(main_mod.parse_arguments(["user", "add", "cli-user", "--role", "analyst"]))
    assert accounts.get_user_by_name("cli-user")["role"] == "analyst"
    assert accounts.query_audit(action="user.create")[0]["actor"] == "cli"

    with pytest.raises(SystemExit):  # a password can never be passed as an argument
        main_mod.parse_arguments(["user", "add", "x-user", "--role", "viewer", "--password", "p"])

    mismatch = iter(["first long password", "second long password"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(mismatch))
    with pytest.raises(SystemExit) as exc:
        main_mod.handle_user(main_mod.parse_arguments(["user", "reset-password", "cli-user"]))
    assert exc.value.code == 2

    c, _ = session_client("cli-user", password="cli user long password")
    main_mod.handle_user(main_mod.parse_arguments(["user", "disable", "cli-user"]))
    assert c.get("/api/v1/stats").status_code == 401
    main_mod.handle_user(main_mod.parse_arguments(["user", "list"]))
    assert "cli-user" in capsys.readouterr().out and "disabled" in capsys.readouterr().out + "disabled"

    c2, _ = session_client("viewer")
    again = iter(["replacement long password"] * 2)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(again))
    main_mod.handle_user(main_mod.parse_arguments(["user", "reset-password", users["viewer"]]))
    assert c2.get("/api/v1/stats").status_code == 401  # reset ends the user's sessions
    with pytest.raises(SystemExit):
        main_mod.handle_user(main_mod.parse_arguments(["user", "disable", "ghost-user"]))


def test_api_refuses_to_serve_without_an_admin(monkeypatch, capsys):
    from unittest.mock import patch

    with patch("waitress.serve") as serve:
        with pytest.raises(SystemExit) as exc:
            main_mod.handle_api(main_mod.parse_arguments(["api"]))
    assert exc.value.code == 2 and "user add" in capsys.readouterr().out
    serve.assert_not_called()


def test_api_process_cannot_write_alerts_db(users):
    from database.database import get_readonly_connection

    conn = get_readonly_connection()
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        conn.execute("DELETE FROM alerts")
    conn.close()
