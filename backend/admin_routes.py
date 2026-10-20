"""Admin-only routes: users, API keys, session revocation, audit log."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from flask import Blueprint, jsonify, request

from backend import accounts
from backend.auth import client_ip, current_identity, require
from backend.common import error_response, valid_id

bp = Blueprint("admin", __name__)


def _actor() -> str:
    ident = current_identity()
    assert ident is not None  # nosec B101
    return ident.actor


def _body(allowed: set[str]) -> dict[str, Any] | None:
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or set(body) - allowed:
        return None
    return body


def _fail(exc: accounts.AccountError):
    return error_response(str(exc), 404 if "No such" in str(exc) else 400)


def _user_action(user_id: int, fn: Callable[[str], Any]):
    user = accounts.get_user(user_id) if valid_id(user_id) else None
    if user is None:
        return error_response("No such user.", 404)
    try:
        return fn(user["username"])
    except accounts.AccountError as exc:
        return _fail(exc)


@bp.get("/api/v1/users")
@require("users:manage")
def list_users():
    return jsonify(accounts.list_users()), 200


@bp.post("/api/v1/users")
@require("users:manage")
def create_user():
    body = _body({"username", "password", "role"})
    if body is None or not all(isinstance(body.get(k), str) for k in ("username", "password", "role")):
        return error_response("Expected JSON with string fields username, password, role.", 400)
    try:
        user_id = accounts.create_user(body["username"], body["password"], body["role"], _actor(), client_ip())
    except accounts.AccountError as exc:
        return _fail(exc)
    return jsonify({"id": user_id, "username": body["username"], "role": body["role"]}), 201


@bp.post("/api/v1/users/<int:user_id>/disable")
@require("users:manage")
def disable_user(user_id: int):
    def act(name: str):
        accounts.set_disabled(name, True, _actor(), client_ip())
        return "", 204

    return _user_action(user_id, act)


@bp.post("/api/v1/users/<int:user_id>/enable")
@require("users:manage")
def enable_user(user_id: int):
    def act(name: str):
        accounts.set_disabled(name, False, _actor(), client_ip())
        return "", 204

    return _user_action(user_id, act)


@bp.post("/api/v1/users/<int:user_id>/reset-password")
@require("users:manage")
def reset_password(user_id: int):
    body = _body({"password"})
    if body is None or not isinstance(body.get("password"), str):
        return error_response("Expected JSON with string field password.", 400)

    def act(name: str):
        accounts.set_password(name, body["password"], _actor(), client_ip())
        return "", 204

    return _user_action(user_id, act)


@bp.post("/api/v1/users/<int:user_id>/revoke-sessions")
@require("users:manage")
def revoke_sessions(user_id: int):
    def act(name: str):
        return jsonify({"revoked": accounts.revoke_user_sessions(name, _actor(), client_ip())}), 200

    return _user_action(user_id, act)


@bp.get("/api/v1/apikeys")
@require("apikeys:manage")
def list_keys():
    return jsonify(accounts.list_api_keys()), 200


@bp.post("/api/v1/apikeys")
@require("apikeys:manage")
def create_key():
    body = _body({"name", "role"})
    if body is None or not all(isinstance(body.get(k), str) for k in ("name", "role")):
        return error_response("Expected JSON with string fields name and role.", 400)
    try:
        key_id, raw = accounts.create_api_key(body["name"], body["role"], _actor(), client_ip())
    except accounts.AccountError as exc:
        return _fail(exc)
    return jsonify({"id": key_id, "key": raw, "note": "Store this key now; it is not shown again."}), 201


@bp.delete("/api/v1/apikeys/<int:key_id>")
@require("apikeys:manage")
def revoke_key(key_id: int):
    if not valid_id(key_id):
        return error_response("No such active API key.", 404)
    try:
        accounts.revoke_api_key(key_id, _actor(), client_ip())
    except accounts.AccountError as exc:
        return _fail(exc)
    return "", 204


@bp.get("/api/v1/audit")
@require("audit:read")
def read_audit():
    allowed = {"limit", "offset", "action", "actor", "since", "target"}
    unknown = set(request.args) - allowed
    if unknown:
        return error_response(f"Unknown query parameter(s): {', '.join(sorted(unknown))}.", 400)
    try:
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
    except ValueError:
        return error_response("limit and offset must be integers.", 400)
    if not 1 <= limit <= 500 or offset < 0:
        return error_response("limit must be 1-500 and offset >= 0.", 400)
    since = request.args.get("since")
    if since:
        try:
            if datetime.fromisoformat(since).tzinfo is None:
                raise ValueError
        except ValueError:
            return error_response("since must be a timezone-aware ISO-8601 timestamp.", 400)
    rows = accounts.query_audit(
        limit, offset, request.args.get("action"), request.args.get("actor"), since, request.args.get("target")
    )
    return jsonify(rows), 200
