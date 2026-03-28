"""Multi-user TCP file server with authentication, session tokens and file isolation."""

import json
import logging
import os
import socket
import ssl
import threading
from typing import Optional

from auth import get_username_from_token, handle_login, handle_logout, hash_password
from config import TLS_ENABLED, get_env, load_dotenv, validate_server_tls_config
from protocol import recv_json, send_json
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


def log_request_event(level: int, action: str, status: str, client_ip: str, reason: Optional[str] = None) -> None:
    """Log one structured request or connection event."""
    message = f"event=request action={action} status={status} client_ip={client_ip}"
    if reason:
        message += f" reason={reason}"
    logging.log(level, message)


def load_users() -> dict:
    """Load the JSON user database from disk, or return an empty structure."""
    if not os.path.exists(USERS_FILE):
        return {"users": {}}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        logging.error("event=startup action=load_users status=failure reason=invalid_json error=%s", exc)
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
        return {"status": "error", "message": "Username and password required"}
    if not is_safe_username(username):
        return {"status": "error", "message": "Invalid username"}
    if username in users["users"]:
        return {"status": "error", "message": "User already exists"}
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
    if not payload:
        log_request_event(logging.WARNING, "unknown", "failure", addr[0], "empty_payload")
        return {"status": "error", "message": "Empty payload"}
    action = payload.get("action")
    if action == "register":
        response = state.register(payload)
        logging.info(
            "event=request action=register status=%s client_ip=%s username=%s reason=%s",
            "success" if response.get("status") == "ok" else "failure",
            addr[0],
            payload.get("username", ""),
            response.get("message", ""),
        )
        return response
    if action == "login":
        response = state.login(payload, addr)
        if response.get("status") == "ok":
            logging.info(
                "event=request action=login status=success client_ip=%s username=%s",
                addr[0],
                payload.get("username", ""),
            )
        else:
            logging.info(
                "event=request action=login status=failure client_ip=%s username=%s reason=%s",
                addr[0],
                payload.get("username", ""),
                response.get("message", ""),
            )
        return response
    if action == "logout":
        response = state.logout(payload)
        logging.info(
            "event=request action=logout status=%s client_ip=%s reason=%s",
            "success" if response.get("status") == "ok" else "failure",
            addr[0],
            response.get("message", ""),
        )
        return response
    if action in {"list", "upload", "download"}:
        username = state.get_username_from_token(payload)
        if not username:
            log_request_event(logging.INFO, action, "failure", addr[0], "not_authenticated")
            return {"status": "error", "message": "Not authenticated"}
        if action == "list":
            response = handle_list(username)
            logging.info(
                "event=request action=list status=success client_ip=%s username=%s file_count=%s",
                addr[0],
                username,
                len(response.get("files", [])),
            )
            return response
        if action == "upload":
            return handle_upload(payload, username, conn, file_locks, addr[0])
        return handle_download(payload, username, conn, file_locks, addr[0])
    log_request_event(logging.WARNING, str(action), "failure", addr[0], "unknown_action")
    return {"status": "error", "message": "Unknown action"}


def handle_client(
    conn: socket.socket,
    addr: tuple,
    state: ServerState,
    file_locks: FileLockRegistry,
) -> None:
    """Serve one connected client until it disconnects or sends invalid data."""
    with conn:
        logging.info("event=connection action=connect status=success client_ip=%s client_port=%s", addr[0], addr[1])
        while True:
            try:
                payload = recv_json(conn)
            except socket.timeout:
                logging.info(
                    "event=connection action=disconnect status=success client_ip=%s client_port=%s reason=socket_timeout",
                    addr[0],
                    addr[1],
                )
                break
            except json.JSONDecodeError:
                logging.warning(
                    "event=request action=decode_json status=failure client_ip=%s client_port=%s reason=invalid_json",
                    addr[0],
                    addr[1],
                )
                break
            except ConnectionError:
                logging.info(
                    "event=connection action=disconnect status=success client_ip=%s client_port=%s reason=client_closed",
                    addr[0],
                    addr[1],
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
        logging.info(
            "event=server action=start status=success host=%s port=%s mode=%s timeout_seconds=%s",
            SERVER_HOST,
            SERVER_PORT,
            mode,
            SOCKET_TIMEOUT_SECONDS,
        )

        while True:
            conn, addr = server_sock.accept()
            if ssl_context is not None:
                try:
                    conn = ssl_context.wrap_socket(conn, server_side=True)
                except ssl.SSLError as exc:
                    logging.warning(
                        "event=connection action=tls_handshake status=failure client_ip=%s client_port=%s reason=ssl_error error=%s",
                        addr[0],
                        addr[1],
                        exc,
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
