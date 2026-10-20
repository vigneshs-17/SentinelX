"""
Authentication, authorization (default deny), CSRF/Origin checks and login throttling for the API.

Every view must carry exactly one policy via a decorator:
    @public                     reachable without credentials (allow-list: /health, /login, dashboard shell)
    @require("alerts:read")     needs a permission; the table below maps permissions to roles in one place
A view with no policy is refused with 403 by the global before_request hook, and a test fails if any route in
app.url_map lacks a policy.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
from typing import Any
from urllib.parse import urlsplit

from flask import Flask, Response, current_app, g, request

from backend import accounts
from backend.common import QUERY_PARAMS, error_response
from backend.ratelimit import limiter
from config.settings import (
    API_RATE_LIMIT_PER_MIN,
    HTTPS_ENABLED,
    LOGIN_LOCK_BASE_SECONDS,
    LOGIN_LOCK_MAX_SECONDS,
    LOGIN_MAX_FAILURES,
    LOGIN_RATE_LIMIT_PER_MIN,
    LOGIN_WINDOW_SECONDS,
    TRUSTED_PROXIES,
)
from detection.state_store import BoundedStateStore

logger = logging.getLogger("sentinelx.auth")

SESSION_COOKIE = "sx_session"
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
PUBLIC = "public"

# One table: permission -> roles that hold it. Anything not listed here is denied.
PERMISSIONS: dict[str, frozenset[str]] = {
    "session:use": frozenset({"viewer", "analyst", "admin"}),
    "alerts:read": frozenset({"viewer", "analyst", "admin"}),
    "metrics:read": frozenset({"viewer", "analyst", "admin"}),
    "alerts:triage": frozenset({"analyst", "admin"}),
    "users:manage": frozenset({"admin"}),
    "apikeys:manage": frozenset({"admin"}),
    "audit:read": frozenset({"admin"}),
}

# Per-process counters surfaced in /api/v1/metrics.
auth_metrics: dict[str, int] = {"login_success": 0, "login_failures": 0, "login_lockouts": 0}


@dataclass(frozen=True)
class Identity:
    kind: str  # "user" | "apikey"
    id: int
    name: str
    role: str
    csrf_token: str | None = None
    session_id: int | None = None

    @property
    def actor(self) -> str:
        return f"user:{self.name}" if self.kind == "user" else f"apikey:{self.id}"


def public(fn: Callable) -> Callable:
    fn._sx_policy = PUBLIC  # type: ignore[attr-defined]
    return fn


def require(permission: str) -> Callable[[Callable], Callable]:
    if permission not in PERMISSIONS:
        raise ValueError(f"unknown permission: {permission}")

    def decorate(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any):
            return fn(*args, **kwargs)

        wrapper._sx_policy = permission  # type: ignore[attr-defined]
        return wrapper

    return decorate


def current_identity() -> Identity | None:
    return getattr(g, "identity", None)


def _trusted(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in ipaddress.ip_network(p, strict=False) for p in TRUSTED_PROXIES)
    except ValueError:
        return False


_xff_warned = False


def _warn_xff_once() -> None:
    global _xff_warned
    if not _xff_warned:
        _xff_warned = True
        logger.warning(
            "X-Forwarded-For seen but SENTINELX_TRUSTED_PROXIES is unset: the header is ignored and every client "
            "behind a proxy shares the proxy's address (one rate-limit and lockout bucket). Set "
            "SENTINELX_TRUSTED_PROXIES to the proxy address(es) if you run behind one."
        )


def client_ip() -> str | None:
    """
    The peer address. X-Forwarded-For is honoured only when the direct peer is in SENTINELX_TRUSTED_PROXIES,
    and then the right-most address that is not itself a trusted proxy is used (earlier entries are client-supplied).
    """
    remote = request.remote_addr
    if not TRUSTED_PROXIES and request.headers.get("X-Forwarded-For"):
        _warn_xff_once()
    if remote and TRUSTED_PROXIES and _trusted(remote):
        for hop in reversed([h.strip() for h in request.headers.get("X-Forwarded-For", "").split(",") if h.strip()]):
            try:
                ipaddress.ip_address(hop)
            except ValueError:
                break  # malformed entry: stop trusting the header
            if not _trusted(hop):
                return hop
    return remote


# ------------------------------------------------------------------ login throttle


class LoginThrottle:
    """
    Failure counters per (client IP, username) pair and per IP (bounded memory). After LOGIN_MAX_FAILURES
    failures of one pair inside the window, that pair is refused for base * 2**(extra failures), capped, counted
    from the last failure. A per-IP counter (IP_FAILURE_FACTOR x the pair limit, all usernames together) stops one
    address from guessing across many usernames. There is deliberately no per-username counter: a global
    username lock lets anyone lock any account out from anywhere. The pair key uses the typed string whether or
    not the user exists, so it leaks nothing.
    """

    IP_FAILURE_FACTOR = 4

    def __init__(self) -> None:
        self._failures: BoundedStateStore[list[float]] = BoundedStateStore("login_failures", 10000)

    def _recent(self, key: str) -> list[float]:
        t = accounts.now()
        return [x for x in (self._failures.get(key) or []) if t - x < LOGIN_WINDOW_SECONDS]

    @staticmethod
    def _keys(ip: str | None, username: str) -> tuple[tuple[str, int], tuple[str, int]]:
        return (f"pair:{ip}|{username.lower()}", LOGIN_MAX_FAILURES), (
            f"ip:{ip}",
            LOGIN_MAX_FAILURES * LoginThrottle.IP_FAILURE_FACTOR,
        )

    def retry_after(self, ip: str | None, username: str) -> float:
        t = accounts.now()
        wait = 0.0
        for key, limit in self._keys(ip, username):
            fails = self._recent(key)
            if len(fails) >= limit:
                delay = min(LOGIN_LOCK_MAX_SECONDS, LOGIN_LOCK_BASE_SECONDS * 2 ** (len(fails) - limit))
                wait = max(wait, delay - (t - fails[-1]))
        return max(0.0, wait)

    def record_failure(self, ip: str | None, username: str) -> None:
        t = accounts.now()
        for key, _ in self._keys(ip, username):
            self._failures.put(key, [*self._recent(key), t])

    def clear_pair(self, ip: str | None, username: str) -> None:
        self._failures.pop(self._keys(ip, username)[0][0])

    def reset(self) -> None:
        self._failures.clear()


throttle = LoginThrottle()


# ------------------------------------------------------------------ request checks


def _origin_ok() -> bool:
    """A browser-supplied Origin must match this server's host. A missing Origin is left to the CSRF token."""
    origin = request.headers.get("Origin")
    if origin is None:
        return True
    return origin != "null" and urlsplit(origin).netloc == request.host


def _authenticate() -> tuple[Identity | None, str]:
    """Returns (identity, credential_kind). Bearer keys never fall back to cookies."""
    header = request.headers.get("Authorization", "")
    if header:
        scheme, _, value = header.partition(" ")
        if scheme.lower() != "bearer" or not value:
            return None, "bearer"
        key = accounts.lookup_api_key(value.strip())
        if key is None:
            return None, "bearer"
        return Identity("apikey", key["id"], key["name"], key["role"]), "bearer"
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        sess = accounts.lookup_session(token)
        if sess is not None:
            return (
                Identity(
                    "user", sess["user_id"], sess["username"], sess["role"], sess["csrf_token"], sess["session_id"]
                ),
                "cookie",
            )
    return None, "cookie"


def _too_many(decision) -> tuple[Response, int]:
    resp = error_response(f"Rate limit exceeded. Retry in {decision.retry_after} seconds.", 429)
    resp[0].headers["Retry-After"] = str(decision.retry_after)
    return resp


def enforce() -> Response | tuple[Response, int] | None:
    """Global before_request: default deny, authenticate, CSRF/Origin, permission."""
    if request.endpoint is None or request.method == "OPTIONS":
        return None  # unknown URL: Flask answers 404; CORS preflights carry no credentials and return no data
    policy = getattr(current_app.view_functions.get(request.endpoint), "_sx_policy", None)
    if policy is None:
        return error_response("This endpoint has no access policy.", 403)

    unsafe = request.method in UNSAFE_METHODS
    unknown = (
        set(request.args) - QUERY_PARAMS.get(request.endpoint, frozenset())
        if request.endpoint != "static_files"
        else set()
    )
    if policy == PUBLIC:
        if unknown:
            return error_response(f"Unknown query parameter(s): {', '.join(sorted(unknown))}.", 400)
        if unsafe and not _origin_ok():
            return error_response("Cross-origin request refused.", 403)
        if request.path == "/login" and unsafe:
            decision = limiter.check(f"login:{client_ip()}", LOGIN_RATE_LIMIT_PER_MIN)
            g.ratelimit = decision
            if not decision.allowed:
                return _too_many(decision)
        return None

    identity, kind = _authenticate()
    if request.path.startswith("/api/v1/"):
        decision = limiter.check(identity.actor if identity else f"ip:{client_ip()}", API_RATE_LIMIT_PER_MIN)
        g.ratelimit = decision
        if not decision.allowed:
            return _too_many(decision)
    if identity is None:
        resp = error_response("Authentication required.", 401)
        if kind == "bearer":
            resp[0].headers["WWW-Authenticate"] = "Bearer"
        return resp
    if identity.kind == "user" and unsafe:
        if not _origin_ok():
            return error_response("Cross-origin request refused.", 403)
        sent = request.headers.get("X-CSRF-Token", "")
        if not identity.csrf_token or not hmac.compare_digest(sent.encode(), identity.csrf_token.encode()):
            return error_response("Missing or invalid CSRF token.", 403)
    if identity.role not in PERMISSIONS[policy]:
        return error_response("You don't have permission for this.", 403)
    if unknown:
        return error_response(f"Unknown query parameter(s): {', '.join(sorted(unknown))}.", 400)
    g.identity = identity
    return None


def init_auth(app: Flask) -> None:
    """Install the default-deny hook."""
    app.before_request(enforce)


def session_cookie_kwargs() -> dict[str, Any]:
    return {"httponly": True, "samesite": "Strict", "path": "/", "secure": HTTPS_ENABLED}
