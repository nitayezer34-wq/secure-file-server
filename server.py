"""Multi-user TCP file server with authentication, session tokens and file isolation."""

import json
import logging
import os
import socket
import ssl
import threading
import time
from typing import Optional

from auth import get_username_from_token, handle_login, handle_logout, hash_password
from config import TLS_ENABLED, get_env, load_dotenv, validate_server_tls_config
from logging_utils import log_event
from protocol import PROTOCOL_VERSION, build_response, error_response, recv_json, send_json
from storage import (
    FileLockRegistry,
    build_user_dir,
    handle_download,
    handle_list,
    handle_upload,
    is_safe_username,
)

load_dotenv()

USERS_FILE = get_env("USERS_FILE", "users.json", str)
STORAGE_DIR = get_env("STORAGE_DIR", "storage", str)
LOG_FILE = get_env("LOG_FILE", "server.log", str)
MAX_FILE_SIZE = get_env("MAX_FILE_SIZE", 10 * 1024 * 1024, int)
SERVER_HOST = get_env("SERVER_HOST", "127.0.0.1", str)
SERVER_PORT = get_env("SERVER_PORT", 9000, int)
SOCKET_TIMEOUT_SECONDS = get_env("SOCKET_TIMEOUT_SECONDS", 30, int)
REQUEST_SCHEMA = {
    "register": {"username": str, "password": str},
    "login": {"username": str, "password": str},
    "logout": {"token": str},
    "list": {"token": str},
    "upload": {"token": str, "filename": str, "size": int, "sha256": str},
    "download": {"token": str, "filename": str},
}


def elapsed_ms(start_time: float) -> int:
    """Return elapsed milliseconds from a perf_counter start time."""
    return int((time.perf_counter() - start_time) * 1000)


def finalize_response(response: dict, request_id: Optional[str]) -> dict:
    """Attach protocol metadata to application responses."""
    if not response:
        return {}
    payload = dict(response)
    status = payload.pop("status", "ok")
    wrapped = build_response(status=status, request_id=request_id, **payload)
    if status == "error":
        wrapped.setdefault("error_code", "REQUEST_FAILED")
        wrapped.setdefault("message", "Request failed")
    return wrapped


def validate_request(payload: dict) -> Optional[dict]:
    """Validate the protocol envelope and required fields."""
    if not isinstance(payload, dict):
        return error_response("INVALID_REQUEST", "Request body must be a JSON object.")
    protocol_version = payload.get("protocol_version")
    request_id = payload.get("request_id")
    action = payload.get("action")

    if protocol_version is None:
        return error_response(
            "MISSING_PROTOCOL_VERSION",
            "protocol_version is required.",
            request_id=request_id if isinstance(request_id, str) else None,
        )
    if not isinstance(protocol_version, int):
        return error_response(
            "INVALID_PROTOCOL_VERSION",
            "protocol_version must be an integer.",
            request_id=request_id if isinstance(request_id, str) else None,
        )
    if protocol_version != PROTOCOL_VERSION:
        return error_response(
            "UNSUPPORTED_PROTOCOL_VERSION",
            f"Unsupported protocol_version: {protocol_version}",
            request_id=request_id if isinstance(request_id, str) else None,
        )
    if not isinstance(request_id, str) or not request_id.strip():
        return error_response("INVALID_REQUEST", "request_id is required and must be a non-empty string.")
    if not isinstance(action, str) or not action.strip():
        return error_response("INVALID_REQUEST", "action is required and must be a non-empty string.", request_id)

    schema = REQUEST_SCHEMA.get(action)
    if schema is None:
        return error_response("UNKNOWN_ACTION", f"Unknown action: {action}", request_id)

    for field_name, expected_type in schema.items():
        value = payload.get(field_name)
        if not isinstance(value, expected_type):
            return error_response(
                "INVALID_REQUEST",
                f"{field_name} must be of type {expected_type.__name__}.",
                request_id,
            )
        if expected_type is str and not value.strip():
            return error_response(
                "INVALID_REQUEST",
                f"{field_name} must be a non-empty string.",
                request_id,
            )
    return None


def load_users() -> dict:
    """Load the JSON user database from disk, or return an empty structure."""
    if not os.path.exists(USERS_FILE):
        return {"users": {}}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        log_event(
            logging.ERROR,
            "server",
            "startup",
            "load_users",
            "failure",
            "-",
            reason="invalid_json",
            error=exc,
        )
        raise RuntimeError(f"Invalid JSON in {USERS_FILE}") from exc


def save_users(data: dict) -> None:
    """Persist the user database to disk."""
    with open(USERS_FILE, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


class ServerState:
    """Thread-safe container for users, active sessions and failed login counters."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.users = load_users()
        self.sessions = {}
        self.login_failures = {}

    def register(self, payload: dict) -> dict:
        """Register a new user under a shared lock."""
        with self._lock:
            return handle_register(payload, self.users)

    def login(self, payload: dict, client_addr: tuple) -> dict:
        """Authenticate a user and create a session token under a shared lock."""
        with self._lock:
            return handle_login(payload, self.users, self.sessions, self.login_failures, client_addr)

    def logout(self, payload: dict) -> dict:
        """Invalidate a session token under a shared lock."""
        with self._lock:
            return handle_logout(payload, self.sessions)

    def get_username_from_token(self, payload: dict) -> Optional[str]:
        """Resolve a session token to a username while checking expiration."""
        with self._lock:
            return get_username_from_token(payload, self.sessions)


def handle_register(payload: dict, users: dict) -> dict:
    """Create a new user account and personal storage directory."""
    username = payload.get("username", "")
    password = payload.get("password", "")
    if not username or not password:
        return {
            "status": "error",
            "error_code": "MISSING_CREDENTIALS",
            "message": "Username and password required",
        }
    if not is_safe_username(username):
        return {"status": "error", "error_code": "INVALID_USERNAME", "message": "Invalid username"}
    if username in users["users"]:
        return {"status": "error", "error_code": "USER_ALREADY_EXISTS", "message": "User already exists"}
    salt = os.urandom(16)
    users["users"][username] = {
        "salt": salt.hex(),
        "password_hash": hash_password(password, salt),
    }
    save_users(users)
    os.makedirs(build_user_dir(username), exist_ok=True)
    return {"status": "ok", "message": "User registered"}

def process_request(
    payload: dict,
    addr: tuple,
    state: ServerState,
    conn: socket.socket,
    file_locks: FileLockRegistry,
) -> dict:
    """Route one decoded request and return the response payload."""
    started_at = time.perf_counter()
    request_id = payload.get("request_id") if isinstance(payload, dict) else None
    validation_error = validate_request(payload)
    if validation_error is not None:
        log_event(
            logging.WARNING,
            "server",
            "request",
            "validate",
            "failure",
            addr[0],
            request_id=request_id,
            error_code=validation_error.get("error_code"),
            reason=validation_error["message"],
            duration_ms=elapsed_ms(started_at),
        )
        return validation_error

    action = payload["action"]
    request_id = payload["request_id"]
    if action == "register":
        response = state.register(payload)
        log_event(
            logging.INFO,
            "server",
            "request",
            "register",
            "success" if response.get("status") == "ok" else "failure",
            addr[0],
            request_id=request_id,
            username=payload.get("username", ""),
            reason=response.get("message", ""),
            error_code=response.get("error_code"),
            duration_ms=elapsed_ms(started_at),
        )
        return finalize_response(response, request_id)
    if action == "login":
        response = state.login(payload, addr)
        log_event(
            logging.INFO,
            "server",
            "request",
            "login",
            "success" if response.get("status") == "ok" else "failure",
            addr[0],
            request_id=request_id,
            username=payload.get("username", ""),
            reason=response.get("message", ""),
            error_code=response.get("error_code"),
            duration_ms=elapsed_ms(started_at),
        )
        return finalize_response(response, request_id)
    if action == "logout":
        response = state.logout(payload)
        log_event(
            logging.INFO,
            "server",
            "request",
            "logout",
            "success" if response.get("status") == "ok" else "failure",
            addr[0],
            request_id=request_id,
            reason=response.get("message", ""),
            error_code=response.get("error_code"),
            duration_ms=elapsed_ms(started_at),
        )
        return finalize_response(response, request_id)
    username = state.get_username_from_token(payload)
    if not username:
        log_event(
            logging.INFO,
            "server",
            "request",
            action,
            "failure",
            addr[0],
            request_id=request_id,
            reason="not_authenticated",
            error_code="AUTH_REQUIRED",
            duration_ms=elapsed_ms(started_at),
        )
        return error_response("AUTH_REQUIRED", "Not authenticated", request_id)
    if action == "list":
        response = handle_list(username)
        log_event(
            logging.INFO,
            "server",
            "request",
            "list",
            "success",
            addr[0],
            request_id=request_id,
            username=username,
            file_count=len(response.get("files", [])),
            duration_ms=elapsed_ms(started_at),
        )
        return finalize_response(response, request_id)
    if action == "upload":
        response = handle_upload(payload, username, conn, file_locks, addr[0], request_id=request_id)
        log_event(
            logging.INFO if response.get("status") == "ok" else logging.WARNING,
            "server",
            "request",
            "upload",
            "success" if response.get("status") == "ok" else "failure",
            addr[0],
            request_id=request_id,
            username=username,
            bytes=payload.get("size"),
            reason=response.get("message", ""),
            error_code=response.get("error_code"),
            duration_ms=elapsed_ms(started_at),
        )
        return finalize_response(response, request_id)
    response = handle_download(payload, username, conn, file_locks, addr[0], request_id=request_id)
    log_event(
        logging.INFO if response.get("status", "ok") == "ok" else logging.WARNING,
        "server",
        "request",
        "download",
        "success" if response.get("status", "ok") == "ok" else "failure",
        addr[0],
        request_id=request_id,
        username=username,
        reason=response.get("message", ""),
        error_code=response.get("error_code"),
        duration_ms=elapsed_ms(started_at),
    )
    return finalize_response(response, request_id)


def handle_client(
    conn: socket.socket,
    addr: tuple,
    state: ServerState,
    file_locks: FileLockRegistry,
) -> None:
    """Serve one connected client until it disconnects or sends invalid data."""
    with conn:
        log_event(
            logging.INFO,
            "server",
            "connection",
            "open",
            "success",
            addr[0],
            client_port=addr[1],
        )
        while True:
            try:
                payload = recv_json(conn)
            except socket.timeout:
                log_event(
                    logging.INFO,
                    "server",
                    "connection",
                    "close",
                    "failure",
                    addr[0],
                    reason="socket_timeout",
                    client_port=addr[1],
                )
                break
            except json.JSONDecodeError:
                log_event(
                    logging.WARNING,
                    "server",
                    "request",
                    "decode_json",
                    "failure",
                    addr[0],
                    reason="invalid_json",
                    client_port=addr[1],
                )
                send_json(conn, error_response("INVALID_JSON", "Request body is not valid JSON."))
                break
            except ssl.SSLError as exc:
                log_event(
                    logging.WARNING,
                    "server",
                    "connection",
                    "tls_session",
                    "failure",
                    addr[0],
                    reason="ssl_error",
                    error=exc,
                    client_port=addr[1],
                )
                break
            except ConnectionError:
                log_event(
                    logging.INFO,
                    "server",
                    "connection",
                    "close",
                    "success",
                    addr[0],
                    reason="client_closed",
                    client_port=addr[1],
                )
                break
            response = process_request(payload, addr, state, conn, file_locks)
            if response:
                send_json(conn, response)


def main():
    """Start the TCP server and spawn one thread per accepted connection."""
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    state = ServerState()
    file_locks = FileLockRegistry()
    os.makedirs(STORAGE_DIR, exist_ok=True)
    ssl_context = None
    if TLS_ENABLED:
        cert_path, key_path = validate_server_tls_config()
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((SERVER_HOST, SERVER_PORT))
        server_sock.listen()
        mode = "TLS" if TLS_ENABLED else "plain TCP"
        log_event(
            logging.INFO,
            "server",
            "server",
            "start",
            "success",
            "-",
            host=SERVER_HOST,
            port=SERVER_PORT,
            mode=mode,
            timeout_seconds=SOCKET_TIMEOUT_SECONDS,
        )

        while True:
            conn, addr = server_sock.accept()
            if ssl_context is not None:
                try:
                    conn = ssl_context.wrap_socket(conn, server_side=True)
                except ssl.SSLError as exc:
                    log_event(
                        logging.WARNING,
                        "server",
                        "connection",
                        "tls_handshake",
                        "failure",
                        addr[0],
                        reason="ssl_error",
                        error=exc,
                        client_port=addr[1],
                    )
                    conn.close()
                    continue
            conn.settimeout(SOCKET_TIMEOUT_SECONDS)
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, state, file_locks),
                daemon=True,
            )
            thread.start()


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        raise SystemExit(f"Server startup failed: {exc}")
