"""Multi-user TCP file server with authentication, session tokens and file isolation."""

import hashlib
import hmac
import json
import logging
import os
import re
import socket
import ssl
import threading
import time
import uuid
from typing import Optional

from config import SERVER_CERT_PATH, SERVER_KEY_PATH, TLS_ENABLED, get_env, load_dotenv
from protocol import recv_json, recv_raw_file, send_json, send_raw_file

load_dotenv()

USERS_FILE = get_env("USERS_FILE", "users.json", str)
STORAGE_DIR = get_env("STORAGE_DIR", "storage", str)
LOG_FILE = get_env("LOG_FILE", "server.log", str)
MAX_FILE_SIZE = get_env("MAX_FILE_SIZE", 10 * 1024 * 1024, int)
MAX_FILENAME_LEN = get_env("MAX_FILENAME_LEN", 255, int)
LOCKOUT_THRESHOLD = get_env("LOCKOUT_THRESHOLD", 5, int)
LOCKOUT_WINDOW_SECONDS = get_env("LOCKOUT_WINDOW_SECONDS", 300, int)
LOCKOUT_DURATION_SECONDS = get_env("LOCKOUT_DURATION_SECONDS", 60, int)
SESSION_TTL_SECONDS = get_env("SESSION_TTL_SECONDS", 60 * 30, int)
PASSWORD_ITERATIONS = get_env("PASSWORD_ITERATIONS", 200_000, int)
SERVER_HOST = get_env("SERVER_HOST", "127.0.0.1", str)
SERVER_PORT = get_env("SERVER_PORT", 9000, int)
FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def load_users() -> dict:
    """Load the JSON user database from disk, or return an empty structure."""
    if not os.path.exists(USERS_FILE):
        return {"users": {}}
    with open(USERS_FILE, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_users(data: dict) -> None:
    """Persist the user database to disk."""
    with open(USERS_FILE, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def hash_password(password: str, salt: bytes) -> str:
    """Derive a password hash using PBKDF2-HMAC-SHA256."""
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return digest.hex()


class ServerState:
    """Thread-safe container for users, active sessions and failed login counters."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.users = load_users()
        self.sessions = {}
        self.attempts = {}

    def register(self, payload: dict) -> dict:
        """Register a new user under a shared lock."""
        with self._lock:
            return handle_register(payload, self.users)

    def login(self, payload: dict, client_addr: tuple) -> dict:
        """Authenticate a user and create a session token under a shared lock."""
        with self._lock:
            return handle_login(payload, self.users, self.sessions, self.attempts, client_addr)

    def logout(self, payload: dict) -> dict:
        """Invalidate a session token under a shared lock."""
        with self._lock:
            return handle_logout(payload, self.sessions)

    def get_username_from_token(self, payload: dict) -> Optional[str]:
        """Resolve a session token to a username while checking expiration."""
        with self._lock:
            return get_username_from_token(payload, self.sessions)


class FileLockRegistry:
    """Provide one in-process lock per file path to avoid concurrent file races."""

    def __init__(self) -> None:
        self._locks = {}
        self._lock = threading.Lock()

    def for_path(self, path: str) -> threading.Lock:
        """Return the lock object associated with a file path."""
        with self._lock:
            lock = self._locks.get(path)
            if lock is None:
                lock = threading.Lock()
                self._locks[path] = lock
            return lock


def handle_register(payload: dict, users: dict) -> dict:
    """Create a new user account and personal storage directory."""
    username = payload.get("username", "")
    password = payload.get("password", "")
    if not username or not password:
        logging.info("register failed: missing fields")
        return {"status": "error", "message": "Username and password required"}
    if username in users["users"]:
        logging.info("register failed: user exists username=%s", username)
        return {"status": "error", "message": "User already exists"}
    salt = os.urandom(16)
    users["users"][username] = {
        "salt": salt.hex(),
        "password_hash": hash_password(password, salt),
    }
    save_users(users)
    os.makedirs(os.path.join(STORAGE_DIR, username), exist_ok=True)
    logging.info("register ok username=%s", username)
    return {"status": "ok", "message": "User registered"}


def handle_login(
    payload: dict,
    users: dict,
    sessions: dict,
    attempts: dict,
    client_addr: tuple,
) -> dict:
    """Validate credentials, enforce lockout policy and issue a session token."""
    username = payload.get("username", "")
    password = payload.get("password", "")
    if not username or not password:
        logging.info("login failed: missing fields")
        return {"status": "error", "message": "Username and password required"}
    lockout_msg = check_lockout(username, attempts)
    if lockout_msg:
        logging.info("login locked out username=%s", username)
        return {"status": "error", "message": lockout_msg}
    user = users["users"].get(username)
    if not user:
        record_failed_login(username, attempts)
        logging.info("login failed: invalid credentials username=%s ip=%s", username, client_addr[0])
        return {"status": "error", "message": "Invalid credentials"}
    salt = bytes.fromhex(user["salt"])
    if not hmac.compare_digest(hash_password(password, salt), user["password_hash"]):
        record_failed_login(username, attempts)
        logging.info("login failed: invalid credentials username=%s ip=%s", username, client_addr[0])
        return {"status": "error", "message": "Invalid credentials"}
    token = uuid.uuid4().hex
    sessions[token] = {
        "username": username,
        "expires_at": time.time() + SESSION_TTL_SECONDS,
    }
    clear_failed_login(username, attempts)
    logging.info("login ok username=%s ip=%s", username, client_addr[0])
    return {"status": "ok", "message": "Login successful", "token": token}


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


def is_safe_filename(filename: str) -> bool:
    """Reject dangerous filenames that could escape the user's folder."""
    if not filename or len(filename) > MAX_FILENAME_LEN:
        return False
    if os.path.basename(filename) != filename:
        return False
    if ".." in filename or "/" in filename or "\\" in filename:
        return False
    return bool(FILENAME_RE.match(filename))


def handle_list(username: str) -> dict:
    """List all regular files that belong to the authenticated user."""
    user_dir = os.path.join(STORAGE_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    files = [
        name
        for name in os.listdir(user_dir)
        if os.path.isfile(os.path.join(user_dir, name))
    ]
    logging.info("list ok username=%s count=%d", username, len(files))
    return {"status": "ok", "files": files}


def handle_upload(payload: dict, username: str, conn: socket.socket, file_locks: FileLockRegistry) -> dict:
    """Receive and verify a file upload for the authenticated user."""
    filename = payload.get("filename", "")
    size = payload.get("size")
    expected_hash = payload.get("sha256", "")
    if not is_safe_filename(filename):
        logging.warning("upload failed: invalid filename username=%s filename=%s", username, filename)
        return {"status": "error", "message": "Invalid filename"}
    if not isinstance(size, int) or size < 0:
        logging.warning("upload failed: invalid size username=%s", username)
        return {"status": "error", "message": "Invalid size"}
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        logging.warning("upload failed: invalid sha256 username=%s filename=%s", username, filename)
        return {"status": "error", "message": "Invalid sha256"}
    if size > MAX_FILE_SIZE:
        logging.warning("upload blocked: too large username=%s size=%d", username, size)
        return {"status": "error", "message": "File too large"}
    send_json(conn, {"status": "ok", "message": "READY"})
    user_dir = os.path.join(STORAGE_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    path = os.path.join(user_dir, filename)
    temp_path = f"{path}.part"
    hasher = hashlib.sha256()
    path_lock = file_locks.for_path(path)
    with path_lock:
        try:
            with open(temp_path, "wb") as handle:
                # Write to a temp file so an interrupted upload doesn't leave partial data.
                recv_raw_file(conn, handle, size, hasher=hasher)
        except (ConnectionError, OSError) as exc:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            logging.info(
                "upload failed: connection error username=%s filename=%s error=%s",
                username,
                filename,
                exc,
            )
            return {"status": "error", "message": "Upload interrupted"}
        received_hash = hasher.hexdigest()
        if received_hash != expected_hash:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            # Integrity check prevents corrupted uploads from being saved.
            logging.info(
                "upload failed: sha256 mismatch username=%s filename=%s expected=%s got=%s",
                username,
                filename,
                expected_hash,
                received_hash,
            )
            return {"status": "error", "message": "sha256 mismatch"}
        # Atomic replace prevents readers from seeing a half-written target file.
        os.replace(temp_path, path)
    logging.info("upload ok username=%s filename=%s size=%d", username, filename, size)
    return {"status": "ok", "message": "Upload complete"}


def handle_download(payload: dict, username: str, conn: socket.socket, file_locks: FileLockRegistry) -> dict:
    """Send a file to the authenticated user together with integrity metadata."""
    filename = payload.get("filename", "")
    if not is_safe_filename(filename):
        logging.info("download failed: invalid filename username=%s filename=%s", username, filename)
        return {"status": "error", "message": "Invalid filename"}
    path = os.path.join(STORAGE_DIR, username, filename)
    if not os.path.isfile(path):
        logging.info("download failed: not found username=%s filename=%s", username, filename)
        return {"status": "error", "message": "File not found"}
    path_lock = file_locks.for_path(path)
    with path_lock:
        size = os.path.getsize(path)
        hasher = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                hasher.update(chunk)
        sha256 = hasher.hexdigest()
        send_json(conn, {"status": "ok", "size": size, "sha256": sha256})
        with open(path, "rb") as handle:
            send_raw_file(conn, handle, size)
    logging.info("download ok username=%s filename=%s size=%d", username, filename, size)
    return {}


def handle_logout(payload: dict, sessions: dict) -> dict:
    """Remove a session token from the active session table."""
    token = payload.get("token")
    if token and token in sessions:
        entry = sessions.pop(token, None)
        username = entry.get("username")
        logging.info("logout ok username=%s", username)
        return {"status": "ok", "message": "Logged out"}
    logging.info("logout failed: invalid token")
    return {"status": "error", "message": "Invalid token"}


def record_failed_login(username: str, attempts: dict) -> None:
    """Track failed logins and start a temporary lockout when needed."""
    entry = attempts.get(username)
    now = time.time()
    if not entry or now - entry["first_fail"] > LOCKOUT_WINDOW_SECONDS:
        attempts[username] = {"count": 1, "first_fail": now, "locked_until": 0}
        return
    if entry["locked_until"] > now:
        return
    entry["count"] += 1
    # Lock when failures reach the threshold inside the window.
    if entry["count"] >= LOCKOUT_THRESHOLD:
        entry["locked_until"] = now + LOCKOUT_DURATION_SECONDS


def clear_failed_login(username: str, attempts: dict) -> None:
    """Clear failed-login counters after a successful authentication."""
    attempts.pop(username, None)


def check_lockout(username: str, attempts: dict) -> Optional[str]:
    """Return a lockout message for blocked users and clear expired lockouts."""
    entry = attempts.get(username)
    if not entry:
        return None
    now = time.time()
    if entry["locked_until"] > now:
        return "Too many failed attempts. Try again later."
    if entry["locked_until"] and entry["locked_until"] <= now:
        # Lockout expired: reset counters.
        attempts.pop(username, None)
        return None
    if now - entry["first_fail"] > LOCKOUT_WINDOW_SECONDS:
        attempts.pop(username, None)
    return None


def handle_client(
    conn: socket.socket,
    addr: tuple,
    state: ServerState,
    file_locks: FileLockRegistry,
) -> None:
    """Serve one connected client until it disconnects or sends invalid data."""
    with conn:
        print(f"Client connected: {addr}")
        while True:
            try:
                payload = recv_json(conn)
            except (ConnectionError, json.JSONDecodeError):
                print(f"Client disconnected: {addr}")
                break
            if not payload:
                send_json(conn, {"status": "error", "message": "Empty payload"})
                continue
            action = payload.get("action")
            if action == "register":
                response = state.register(payload)
            elif action == "login":
                response = state.login(payload, addr)
            elif action == "logout":
                response = state.logout(payload)
            elif action in {"list", "upload", "download"}:
                # All file actions require a valid session token first.
                username = state.get_username_from_token(payload)
                if not username:
                    logging.info("auth failed: missing/invalid token action=%s", action)
                    response = {"status": "error", "message": "Not authenticated"}
                elif action == "list":
                    response = handle_list(username)
                elif action == "upload":
                    response = handle_upload(payload, username, conn, file_locks)
                else:
                    response = handle_download(payload, username, conn, file_locks)
            else:
                response = {"status": "error", "message": "Unknown action"}
            if response:
                send_json(conn, response)


def main():
    """Start the TCP server and spawn one thread per accepted connection."""
    state = ServerState()
    file_locks = FileLockRegistry()
    os.makedirs(STORAGE_DIR, exist_ok=True)
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    ssl_context = None
    if TLS_ENABLED:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=SERVER_CERT_PATH, keyfile=SERVER_KEY_PATH)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((SERVER_HOST, SERVER_PORT))
        server_sock.listen()
        mode = "TLS" if TLS_ENABLED else "plain TCP"
        print(f"Server listening on {SERVER_HOST}:{SERVER_PORT} ({mode})")

        while True:
            conn, addr = server_sock.accept()
            if ssl_context is not None:
                try:
                    conn = ssl_context.wrap_socket(conn, server_side=True)
                except ssl.SSLError as exc:
                    logging.warning("tls handshake failed from %s:%s error=%s", addr[0], addr[1], exc)
                    conn.close()
                    continue
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, state, file_locks),
                daemon=True,
            )
            thread.start()


if __name__ == "__main__":
    main()
