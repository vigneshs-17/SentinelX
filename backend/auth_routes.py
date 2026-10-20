"""Login, logout, current session, and alert triage routes."""

from __future__ import annotations

from typing import Any

from flask import Blueprint, jsonify, make_response, request

from backend import accounts, passwords
from backend.auth import (
    SESSION_COOKIE,
    auth_metrics,
    client_ip,
    current_identity,
    public,
    require,
    session_cookie_kwargs,
    throttle,
)
from backend.common import error_response, valid_id
from config.settings import TRIAGE_NOTE_MAX_CHARS
from database.database import get_readonly_connection

bp = Blueprint("auth", __name__)

GENERIC_LOGIN_ERROR = "Invalid username or password."


def _json_body() -> dict[str, Any] | None:
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


@bp.post("/login")
@public
def login():
    body = _json_body()
    username, password = (body or {}).get("username"), (body or {}).get("password")
    if not isinstance(username, str) or not isinstance(password, str) or not (1 <= len(username) <= 64) or not password:
        return error_response("username and password are required.", 400)
    ip = client_ip()

    wait = throttle.retry_after(ip, username)
    if wait > 0:
        auth_metrics["login_lockouts"] += 1
        seconds = int(wait) + 1
        resp = error_response(f"Too many attempts. Try again in {seconds} seconds.", 429)
        resp[0].headers["Retry-After"] = str(seconds)
        return resp

    user = accounts.get_user_by_name(username)
    usable = user is not None and not user["disabled"]
    # Unknown or disabled users still pay for one Argon2 verification (against a dummy hash).
    valid = passwords.verify_password(user["password_hash"] if usable and user else None, password)
    if not (usable and valid and user):
        throttle.record_failure(ip, username)
        auth_metrics["login_failures"] += 1
        accounts.audit("login.failure", "anonymous", ip, f"user:{username[:64]}")
        return error_response(GENERIC_LOGIN_ERROR, 401)

    # Session fixation: never reuse an incoming session; drop it and mint a fresh id.
    old = request.cookies.get(SESSION_COOKIE)
    if old:
        accounts.delete_session(old)
    new_hash = passwords.hash_password(password) if passwords.needs_rehash(user["password_hash"]) else None
    accounts.touch_login(user["id"], new_hash)
    throttle.clear_pair(ip, username)
    token, csrf = accounts.create_session(user["id"], ip)
    auth_metrics["login_success"] += 1
    accounts.audit("login.success", f"user:{user['username']}", ip, f"user:{user['username']}")

    resp = make_response(
        jsonify({"user": {"username": user["username"], "role": user["role"]}, "csrf_token": csrf}), 200
    )
    resp.set_cookie(SESSION_COOKIE, token, **session_cookie_kwargs())
    return resp


@bp.post("/api/v1/logout")
@require("session:use")
def logout():
    ident = current_identity()
    token = request.cookies.get(SESSION_COOKIE)
    if ident and ident.kind == "user" and token:
        accounts.delete_session(token)
        accounts.audit("logout", ident.actor, client_ip(), ident.actor)
    resp = make_response("", 204)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@bp.get("/api/v1/session")
@require("session:use")
def whoami():
    ident = current_identity()
    assert ident is not None  # nosec B101
    return jsonify({"kind": ident.kind, "name": ident.name, "role": ident.role, "csrf_token": ident.csrf_token}), 200


def _alert_exists(alert_id: int) -> bool:
    conn = get_readonly_connection()
    try:
        return conn.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is not None
    finally:
        conn.close()


@bp.get("/api/v1/alerts/<int:alert_id>/triage")
@require("alerts:read")
def get_triage(alert_id: int):
    if not valid_id(alert_id) or not _alert_exists(alert_id):
        return error_response("No such alert.", 404)
    history = accounts.query_audit(limit=200, action="triage.update", target=f"alert:{alert_id}")
    return jsonify({"alert_id": alert_id, "triage": accounts.get_triage(alert_id), "history": history}), 200


@bp.post("/api/v1/alerts/<int:alert_id>/triage")
@require("alerts:triage")
def post_triage(alert_id: int):
    if not valid_id(alert_id):
        return error_response("No such alert.", 404)
    body = _json_body()
    if body is None:
        return error_response("Expected a JSON object.", 400)
    try:
        fields = accounts.validate_triage(body, TRIAGE_NOTE_MAX_CHARS)
    except accounts.AccountError as exc:
        return error_response(str(exc), 400)
    if not _alert_exists(alert_id):
        return error_response("No such alert.", 404)
    ident = current_identity()
    assert ident is not None  # nosec B101
    return jsonify(accounts.set_triage(alert_id, fields, ident.actor, client_ip())), 200


@bp.get("/api/v1/assignees")
@require("alerts:triage")
def list_assignees():
    """Usernames an analyst may assign alerts to (enabled users only; no other user data)."""
    return jsonify(sorted(u["username"] for u in accounts.list_users() if not u["disabled"])), 200
