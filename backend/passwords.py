"""Password policy and Argon2id hashing (argon2-cffi library-recommended parameters)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from config.settings import PASSWORD_MIN_LENGTH

MAX_PASSWORD_LENGTH = 1024  # bound hashing cost for hostile inputs
_COMMON_FILE = Path(__file__).resolve().parent / "common_passwords.txt"

_hasher = PasswordHasher()  # RFC 9106 low-memory profile, the library default


@lru_cache(maxsize=1)
def _common_passwords() -> frozenset[str]:
    return frozenset(
        line.strip().lower() for line in _COMMON_FILE.read_text(encoding="utf-8").splitlines() if line.strip()
    )


def validate_password(password: str, username: str | None = None) -> str | None:
    """Return an error message, or None when the password is acceptable."""
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
    lowered = password.lower()
    if lowered in _common_passwords():
        return "That password is too common."
    if username and lowered == username.lower():
        return "Password must not equal the username."
    return None


def hash_password(password: str) -> str:
    return _hasher.hash(password)


@lru_cache(maxsize=1)
def dummy_hash() -> str:
    """A valid hash of a random-looking constant, verified for unknown users so timing does not reveal them."""
    return _hasher.hash("sentinelx-dummy-password-for-timing-equalisation")


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Verify against stored_hash, or against the dummy hash when it is None. Always costs one Argon2 verify."""
    target = stored_hash if stored_hash is not None else dummy_hash()
    try:
        _hasher.verify(target, password[:MAX_PASSWORD_LENGTH])
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return stored_hash is not None


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)
