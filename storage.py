"""Storage and file handling helpers for the file server."""

import hashlib
import logging
import os
import re
import socket
import threading

from config import get_env
from protocol import recv_raw_file, send_json, send_raw_file

STORAGE_DIR = get_env("STORAGE_DIR", "storage", str)
MAX_FILE_SIZE = get_env("MAX_FILE_SIZE", 10 * 1024 * 1024, int)
MAX_FILENAME_LEN = get_env("MAX_FILENAME_LEN", 255, int)
MAX_USERNAME_LEN = get_env("MAX_USERNAME_LEN", 64, int)
NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class FileLockRegistry:
    """Provide one in-process lock per file path to avoid concurrent file races."""

    def __init__(self) -> None:
        self._locks = {}
        self._lock = threading.Lock()

    def for_path(self, path: str):
        """Return the lock object associated with a file path."""
        with self._lock:
            lock = self._locks.get(path)
            if lock is None:
                lock = threading.Lock()
                self._locks[path] = lock
            return lock


def is_safe_username(username: str) -> bool:
    """Reject usernames that could escape storage or create ambiguous paths."""
    if not username or len(username) > MAX_USERNAME_LEN:
        return False
    if os.path.basename(username) != username:
        return False
    if ".." in username or "/" in username or "\\" in username:
        return False
    return bool(NAME_RE.fullmatch(username))


def is_safe_filename(filename: str) -> bool:
    """Reject dangerous filenames that could escape the user's folder."""
    if not filename or len(filename) > MAX_FILENAME_LEN:
        return False
    if os.path.basename(filename) != filename:
        return False
    if ".." in filename or "/" in filename or "\\" in filename:
        return False
    return bool(NAME_RE.fullmatch(filename))


def build_user_dir(username: str) -> str:
    """Build the absolute storage path for one validated username."""
    if not is_safe_username(username):
        raise ValueError("Invalid username")
    return os.path.join(STORAGE_DIR, username)


def build_user_file_path(username: str, filename: str) -> str:
    """Build the absolute storage path for one validated user file."""
    if not is_safe_filename(filename):
        raise ValueError("Invalid filename")
    return os.path.join(build_user_dir(username), filename)


def handle_list(username: str) -> dict:
    """List all regular files that belong to the authenticated user."""
    user_dir = build_user_dir(username)
    os.makedirs(user_dir, exist_ok=True)
    files = sorted(
        name
        for name in os.listdir(user_dir)
        if os.path.isfile(os.path.join(user_dir, name))
    )
    return {"status": "ok", "files": files}


def handle_upload(
    payload: dict,
    username: str,
    conn: socket.socket,
    file_locks: FileLockRegistry,
    client_ip: str = "-",
) -> dict:
    """Receive and verify a file upload for the authenticated user."""
    filename = payload.get("filename", "")
    size = payload.get("size")
    expected_hash = payload.get("sha256", "")
    logging.info(
        "event=request action=upload status=start client_ip=%s username=%s filename=%s size=%s",
        client_ip,
        username,
        filename,
        size,
    )
    if not is_safe_filename(filename):
        logging.warning(
            "event=request action=upload status=failure client_ip=%s username=%s filename=%s reason=invalid_filename",
            client_ip,
            username,
            filename,
        )
        return {"status": "error", "message": "Invalid filename"}
    if not isinstance(size, int) or size < 0:
        logging.warning(
            "event=request action=upload status=failure client_ip=%s username=%s filename=%s reason=invalid_size",
            client_ip,
            username,
            filename,
        )
        return {"status": "error", "message": "Invalid size"}
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        logging.warning(
            "event=request action=upload status=failure client_ip=%s username=%s filename=%s reason=invalid_sha256",
            client_ip,
            username,
            filename,
        )
        return {"status": "error", "message": "Invalid sha256"}
    if size > MAX_FILE_SIZE:
        logging.warning(
            "event=request action=upload status=failure client_ip=%s username=%s filename=%s reason=file_too_large size=%s",
            client_ip,
            username,
            filename,
            size,
        )
        return {"status": "error", "message": "File too large"}
    send_json(conn, {"status": "ok", "message": "READY"})
    user_dir = build_user_dir(username)
    os.makedirs(user_dir, exist_ok=True)
    path = build_user_file_path(username, filename)
    temp_path = f"{path}.part"
    hasher = hashlib.sha256()
    path_lock = file_locks.for_path(path)
    with path_lock:
        try:
            with open(temp_path, "wb") as handle:
                recv_raw_file(conn, handle, size, hasher=hasher)
        except (ConnectionError, OSError, socket.timeout) as exc:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            logging.warning(
                "event=request action=upload status=failure client_ip=%s username=%s filename=%s reason=transfer_interrupted error=%s",
                client_ip,
                username,
                filename,
                exc,
            )
            return {"status": "error", "message": "Upload interrupted"}
        received_hash = hasher.hexdigest()
        if received_hash != expected_hash:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            logging.warning(
                "event=request action=upload status=failure client_ip=%s username=%s filename=%s reason=sha256_mismatch expected_sha256=%s received_sha256=%s",
                client_ip,
                username,
                filename,
                expected_hash,
                received_hash,
            )
            return {"status": "error", "message": "sha256 mismatch"}
        os.replace(temp_path, path)
    logging.info(
        "event=request action=upload status=success client_ip=%s username=%s filename=%s size=%s",
        client_ip,
        username,
        filename,
        size,
    )
    return {"status": "ok", "message": "Upload complete"}


def handle_download(
    payload: dict,
    username: str,
    conn: socket.socket,
    file_locks: FileLockRegistry,
    client_ip: str = "-",
) -> dict:
    """Send a file to the authenticated user together with integrity metadata."""
    filename = payload.get("filename", "")
    logging.info(
        "event=request action=download status=start client_ip=%s username=%s filename=%s",
        client_ip,
        username,
        filename,
    )
    if not is_safe_filename(filename):
        logging.warning(
            "event=request action=download status=failure client_ip=%s username=%s filename=%s reason=invalid_filename",
            client_ip,
            username,
            filename,
        )
        return {"status": "error", "message": "Invalid filename"}
    path = build_user_file_path(username, filename)
    if not os.path.isfile(path):
        logging.info(
            "event=request action=download status=failure client_ip=%s username=%s filename=%s reason=file_not_found",
            client_ip,
            username,
            filename,
        )
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
    logging.info(
        "event=request action=download status=success client_ip=%s username=%s filename=%s size=%s",
        client_ip,
        username,
        filename,
        size,
    )
    return {}
