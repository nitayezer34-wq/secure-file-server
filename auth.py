"""Authentication and session helpers for the file server."""

import hashlib
import hmac
import time
import uuid
from typing import Optional

from config import get_env

LOCKOUT_THRESHOLD = get_env("LOCKOUT_THRESHOLD", 5, int)
LOCKOUT_WINDOW_SECONDS = get_env("LOCKOUT_WINDOW_SECONDS", 300, int)
LOCKOUT_DURATION_SECONDS = get_env("LOCKOUT_DURATION_SECONDS", 60, int)
SESSION_TTL_SECONDS = get_env("SESSION_TTL_SECONDS", 60 * 30, int)
PASSWORD_ITERATIONS = get_env("PASSWORD_ITERATIONS", 200_000, int)


def hash_password(password: str, salt: bytes) -> str:
    """Derive a password hash using PBKDF2-HMAC-SHA256."""
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return digest.hex()


def record_failed_login(username: str, login_failures: dict) -> None:
    """Track failed logins and start a temporary lockout when needed."""
    entry = login_failures.get(username)
    now = time.time()
    if not entry or now - entry["first_fail"] > LOCKOUT_WINDOW_SECONDS:
        login_failures[username] = {"count": 1, "first_fail": now, "locked_until": 0}
        return
    if entry["locked_until"] > now:
        return
    entry["count"] += 1
    if entry["count"] >= LOCKOUT_THRESHOLD:
        entry["locked_until"] = now + LOCKOUT_DURATION_SECONDS


def clear_failed_login(username: str, login_failures: dict) -> None:
    """Clear failed-login counters after a successful authentication."""
    login_failures.pop(username, None)


def check_lockout(username: str, login_failures: dict) -> Optional[str]:
    """Return a lockout message for blocked users and clear expired lockouts."""
    entry = login_failures.get(username)
    if not entry:
        return None
    now = time.time()
    if entry["locked_until"] > now:
        return "Too many failed attempts. Try again later."
    if entry["locked_until"] and entry["locked_until"] <= now:
        login_failures.pop(username, None)
        return None
    if now - entry["first_fail"] > LOCKOUT_WINDOW_SECONDS:
        login_failures.pop(username, None)
    return None


def get_username_from_token(payload: dict, sessions: dict) -> Optional[str]:
    """Return the username for a valid session token or None otherwise."""
    token = payload.get("token")
    if not token:
        return None
    entry = sessions.get(token)
    if not entry:
        return None
    if entry["expires_at"] < time.time():
        sessions.pop(token, None)
        return None
    return entry["username"]


def handle_login(
    payload: dict,
    users: dict,
    sessions: dict,
    login_failures: dict,
    client_addr: tuple,
) -> dict:
    """Validate credentials, enforce lockout policy and issue a session token."""
    username = payload.get("username", "")
    password = payload.get("password", "")
    if not username or not password:
        return {"status": "error", "message": "Username and password required"}
    lockout_msg = check_lockout(username, login_failures)
    if lockout_msg:
        return {"status": "error", "message": lockout_msg}
    user = users["users"].get(username)
    if not user:
        record_failed_login(username, login_failures)
        return {"status": "error", "message": "Invalid credentials"}
    salt = bytes.fromhex(user["salt"])
    if not hmac.compare_digest(hash_password(password, salt), user["password_hash"]):
        record_failed_login(username, login_failures)
        return {"status": "error", "message": "Invalid credentials"}
    token = uuid.uuid4().hex
    sessions[token] = {
        "username": username,
        "expires_at": time.time() + SESSION_TTL_SECONDS,
    }
    clear_failed_login(username, login_failures)
    return {"status": "ok", "message": "Login successful", "token": token}


def handle_logout(payload: dict, sessions: dict) -> dict:
    """Remove a session token from the active session table."""
    token = payload.get("token")
    if token and token in sessions:
        sessions.pop(token, None)
        return {"status": "ok", "message": "Logged out"}
    return {"status": "error", "message": "Invalid token"}
