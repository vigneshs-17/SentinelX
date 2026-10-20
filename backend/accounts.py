"""
Accounts, sessions, API keys, triage state and the audit log (all in app.db).

Used by both the CLI (`main.py user ...`, `main.py apikey ...`) and the admin routes, so the rules live once.
Secrets handling: passwords are Argon2id hashes; session tokens and API keys are stored only as SHA-256 hashes
(they are 256-bit random values, so a fast hash is appropriate); none of them is ever written to the audit log.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from backend import passwords
from config.settings import SESSION_ABSOLUTE_SECONDS, SESSION_IDLE_SECONDS
from database.app_db import AUDIT_NO_DELETE_TRIGGER, AppDatabaseError, get_app_connection

ROLES = ("viewer", "analyst", "admin")
KEY_ROLES = ("viewer", "analyst")
TRIAGE_STATUSES = ("new", "acknowledged", "investigating", "resolved_tp", "resolved_fp")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
KEY_PREFIX = "sx_"
FORBIDDEN_AUDIT_KEYS = frozenset({"password", "token", "key", "api_key", "secret", "url", "webhook", "csrf", "hash"})


class AccountError(ValueError):
    """Invalid request (bad username, weak password, unknown user...). Message is safe to show."""


def now() -> float:
    """Wall-clock seconds. Single seam so tests can inject time for session expiry."""
    return time.time()


@contextmanager
def db():
    """app.db connection. Lock/IO errors surface as AppDatabaseError so they are not mistaken for alerts.db ones."""
    try:
        conn = get_app_connection()
    except sqlite3.OperationalError as exc:
        raise AppDatabaseError(str(exc)) from exc
    try:
        yield conn
    except sqlite3.OperationalError as exc:
        raise AppDatabaseError(str(exc)) from exc
    finally:
        conn.close()


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ audit log


def audit(
    action: str,
    actor: str,
    ip: str | None = None,
    target: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Append one audit row. Refuses details that look like secrets (programming error, not user input)."""
    if detail:
        bad = FORBIDDEN_AUDIT_KEYS & {k.lower() for k in detail}
        if bad:
            raise ValueError(f"refusing to audit secret-looking fields: {sorted(bad)}")
    ts = datetime.fromtimestamp(now(), tz=UTC).isoformat(timespec="seconds")
    with db() as conn, conn:
        conn.execute(
            "INSERT INTO audit_log (ts, actor, source_ip, action, target, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (ts, actor[:128], ip, action, target, json.dumps(detail, ensure_ascii=False) if detail else None),
        )


def query_audit(
    limit: int = 100,
    offset: int = 0,
    action: str | None = None,
    actor: str | None = None,
    since: str | None = None,
    target: str | None = None,
) -> list[dict[str, Any]]:
    conds: list[str] = []
    params: list[Any] = []
    for col, val in (("action", action), ("actor", actor), ("target", target)):
        if val:
            conds.append(f"{col} = ?")
            params.append(val)
    if since:
        conds.append("ts >= ?")
        params.append(since)
    where = f"WHERE {' AND '.join(conds)}" if conds else ""
    sql = f"SELECT id, ts, actor, source_ip, action, target, detail FROM audit_log {where} ORDER BY id DESC LIMIT ? OFFSET ?"  # nosec B608
    with db() as conn:
        rows = conn.execute(sql, [*params, limit, offset]).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["detail"] = json.loads(d["detail"]) if d["detail"] else None
        out.append(d)
    return out


def prune_audit(retention_days: int, actor: str = "cli") -> int:
    """
    Admin-run only (`main.py db prune-audit`): delete audit rows older than retention_days. The append-only
    trigger stays in force for everything else: it is dropped and recreated inside one transaction (SQLite DDL is
    transactional), so it is intact whenever the transaction ends, committed or rolled back. 0 = keep forever.
    The prune itself is audited afterwards.
    """
    if retention_days <= 0:
        return 0
    cutoff = (datetime.fromtimestamp(now(), tz=UTC) - timedelta(days=retention_days)).isoformat(timespec="seconds")
    with db() as conn:
        with conn:
            conn.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
            deleted = conn.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,)).rowcount
            conn.execute(AUDIT_NO_DELETE_TRIGGER)
    audit("audit.prune", actor, None, None, {"deleted": int(deleted), "older_than_days": retention_days})
    return int(deleted)


# ------------------------------------------------------------------ users


def _user_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None


def create_user(username: str, password: str, role: str, actor: str = "cli", ip: str | None = None) -> int:
    if not USERNAME_RE.match(username):
        raise AccountError("Username must be 3-64 characters: letters, digits, '.', '_' or '-'.")
    if role not in ROLES:
        raise AccountError(f"Role must be one of: {', '.join(ROLES)}.")
    problem = passwords.validate_password(password, username)
    if problem:
        raise AccountError(problem)
    pw_hash = passwords.hash_password(password)
    try:
        with db() as conn, conn:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, pw_hash, role, now()),
            )
            user_id = int(cur.lastrowid or 0)
    except sqlite3.IntegrityError as exc:
        raise AccountError("That username already exists.") from exc
    audit("user.create", actor, ip, f"user:{username}", {"role": role})
    return user_id


def get_user_by_name(username: str) -> dict[str, Any] | None:
    with db() as conn:
        return _user_dict(conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone())


def get_user(user_id: int) -> dict[str, Any] | None:
    with db() as conn:
        return _user_dict(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())


def list_users() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT id, username, role, disabled, created_at, last_login_at FROM users ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


def _require_user(username: str) -> dict[str, Any]:
    user = get_user_by_name(username)
    if user is None:
        raise AccountError("No such user.")
    return user


def set_password(username: str, password: str, actor: str = "cli", ip: str | None = None) -> None:
    user = _require_user(username)
    problem = passwords.validate_password(password, user["username"])
    if problem:
        raise AccountError(problem)
    with db() as conn, conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (passwords.hash_password(password), user["id"]))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    audit("user.reset_password", actor, ip, f"user:{user['username']}")


def set_disabled(username: str, disabled: bool, actor: str = "cli", ip: str | None = None) -> None:
    user = _require_user(username)
    if disabled and user["role"] == "admin" and not user["disabled"] and _enabled_admin_count() <= 1:
        raise AccountError("Cannot disable the last enabled admin.")
    with db() as conn, conn:
        conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (1 if disabled else 0, user["id"]))
        if disabled:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    audit("user.disable" if disabled else "user.enable", actor, ip, f"user:{user['username']}")


def _enabled_admin_count() -> int:
    with db() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0").fetchone()[0])


def admin_exists() -> bool:
    return _enabled_admin_count() > 0


def revoke_user_sessions(username: str, actor: str = "cli", ip: str | None = None) -> int:
    user = _require_user(username)
    with db() as conn, conn:
        n = conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],)).rowcount
    audit("sessions.revoke_all", actor, ip, f"user:{user['username']}", {"sessions": n})
    return int(n)


def touch_login(user_id: int, new_hash: str | None = None) -> None:
    with db() as conn, conn:
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), user_id))
        if new_hash:
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))


# ------------------------------------------------------------------ sessions


def create_session(user_id: int, ip: str | None) -> tuple[str, str]:
    """New server-side session. Returns (cookie_token, csrf_token); only the token's SHA-256 is stored."""
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    t = now()
    with db() as conn, conn:
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, last_seen_at, source_ip) VALUES (?, ?, ?, ?, ?, ?)",
            (sha256_hex(token), user_id, csrf, t, t, ip),
        )
    return token, csrf


def lookup_session(token: str) -> dict[str, Any] | None:
    """Resolve a cookie token to its session + user, enforcing idle/absolute timeouts and disabled users."""
    token_hash = sha256_hex(token)
    t = now()
    with db() as conn:
        row = conn.execute(
            "SELECT s.id AS session_id, s.csrf_token, s.created_at, s.last_seen_at, u.id AS user_id, "
            "u.username, u.role, u.disabled FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        expired = (t - row["last_seen_at"] > SESSION_IDLE_SECONDS) or (t - row["created_at"] > SESSION_ABSOLUTE_SECONDS)
        if expired or row["disabled"]:
            with conn:
                conn.execute("DELETE FROM sessions WHERE id = ?", (row["session_id"],))
            return None
        with conn:
            conn.execute("UPDATE sessions SET last_seen_at = ? WHERE id = ?", (t, row["session_id"]))
        return dict(row)


def purge_expired_sessions() -> int:
    """Delete sessions past the idle or absolute timeout (lookup only removes the ones somebody presents)."""
    t = now()
    with db() as conn, conn:
        return conn.execute(
            "DELETE FROM sessions WHERE ? - last_seen_at > ? OR ? - created_at > ?",
            (t, SESSION_IDLE_SECONDS, t, SESSION_ABSOLUTE_SECONDS),
        ).rowcount


def delete_session(token: str) -> bool:
    with db() as conn, conn:
        return conn.execute("DELETE FROM sessions WHERE token_hash = ?", (sha256_hex(token),)).rowcount > 0


# ------------------------------------------------------------------ API keys


def create_api_key(name: str, role: str, actor: str = "cli", ip: str | None = None) -> tuple[int, str]:
    """Create a key; returns (id, raw_key). The raw key is shown once and never stored."""
    if role not in KEY_ROLES:
        raise AccountError(f"API key role must be one of: {', '.join(KEY_ROLES)}.")
    name = name.strip()
    if not 1 <= len(name) <= 64 or any(ord(c) < 32 for c in name):
        raise AccountError("API key name must be 1-64 printable characters.")
    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    with db() as conn, conn:
        cur = conn.execute(
            "INSERT INTO api_keys (name, prefix, key_hash, role, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (name, raw[:8], sha256_hex(raw), role, actor, now()),
        )
        key_id = int(cur.lastrowid or 0)
    audit("apikey.create", actor, ip, f"apikey:{key_id}", {"name": name, "role": role})
    return key_id, raw


def lookup_api_key(raw: str) -> dict[str, Any] | None:
    """Resolve a bearer key. Revocation is checked on every call, so it is effective immediately."""
    if not raw.startswith(KEY_PREFIX):
        return None
    with db() as conn:
        row = conn.execute(
            "SELECT id, name, role FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL", (sha256_hex(raw),)
        ).fetchone()
        if row is None:
            return None
        with conn:
            conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now(), row["id"]))
        return dict(row)


def revoke_api_key(key_id: int, actor: str = "cli", ip: str | None = None) -> None:
    with db() as conn, conn:
        n = conn.execute(
            "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", (now(), key_id)
        ).rowcount
    if not n:
        raise AccountError("No such active API key.")
    audit("apikey.revoke", actor, ip, f"apikey:{key_id}")


def list_api_keys() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT id, name, prefix, role, created_by, created_at, last_used_at, revoked_at FROM api_keys ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------ triage


def validate_triage(body: dict[str, Any], max_note: int) -> dict[str, Any]:
    """Validate a triage request body; returns cleaned fields or raises AccountError."""
    unknown = set(body) - {"status", "assignee", "note"}
    if unknown:
        raise AccountError(f"Unknown field(s): {', '.join(sorted(unknown))}.")
    status = body.get("status")
    if status not in TRIAGE_STATUSES:
        raise AccountError(f"status must be one of: {', '.join(TRIAGE_STATUSES)}.")
    assignee = body.get("assignee")
    if assignee is not None:
        if not isinstance(assignee, str) or not USERNAME_RE.match(assignee):
            raise AccountError("assignee must be a username or null.")
        user = get_user_by_name(assignee)
        if user is None or user["disabled"]:
            raise AccountError("assignee must be an existing, enabled user.")
        assignee = user["username"]
    note = body.get("note")
    if note is not None:
        if not isinstance(note, str):
            raise AccountError("note must be text.")
        if len(note) > max_note:
            raise AccountError(f"note must be at most {max_note} characters.")
        if any(ord(c) < 32 and c not in "\n\t" for c in note):
            raise AccountError("note must be plain text (no control characters).")
    return {"status": status, "assignee": assignee, "note": note}


def set_triage(alert_id: int, fields: dict[str, Any], actor: str, ip: str | None) -> dict[str, Any]:
    with db() as conn:
        old = conn.execute("SELECT status FROM triage WHERE alert_id = ?", (alert_id,)).fetchone()
        with conn:
            conn.execute(
                "INSERT INTO triage (alert_id, status, assignee, note, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(alert_id) DO UPDATE SET status=excluded.status, assignee=excluded.assignee, "
                "note=excluded.note, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
                (alert_id, fields["status"], fields["assignee"], fields["note"], actor, now()),
            )
    audit(
        "triage.update",
        actor,
        ip,
        f"alert:{alert_id}",
        {
            "from": old["status"] if old else "new",
            "to": fields["status"],
            "assignee": fields["assignee"],
            "note": fields["note"],
        },
    )
    return get_triage(alert_id) or {}


def get_triage(alert_id: int) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM triage WHERE alert_id = ?", (alert_id,)).fetchone()
    return dict(row) if row else None


def prune_orphan_triage(alerts_conn: sqlite3.Connection) -> int:
    """
    Delete triage rows whose alert no longer exists in alerts.db (removed by retention). alerts_conn is a
    read-only alerts.db connection; alert ids are AUTOINCREMENT, so a deleted id is never reused.
    """
    with db() as conn:
        ids = [r[0] for r in conn.execute("SELECT alert_id FROM triage")]
        gone: list[int] = []
        for i in range(0, len(ids), 500):
            chunk = ids[i : i + 500]
            marks = ",".join("?" * len(chunk))
            present = {r[0] for r in alerts_conn.execute(f"SELECT id FROM alerts WHERE id IN ({marks})", chunk)}  # nosec B608
            gone.extend(a for a in chunk if a not in present)
        deleted = 0
        with conn:
            for i in range(0, len(gone), 500):
                chunk = gone[i : i + 500]
                marks = ",".join("?" * len(chunk))
                deleted += conn.execute(f"DELETE FROM triage WHERE alert_id IN ({marks})", chunk).rowcount  # nosec B608
    return deleted
