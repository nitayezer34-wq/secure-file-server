"""Low-level TCP framing helpers for JSON messages and raw file transfer."""

import json
import struct
import uuid
from typing import Optional


PROTOCOL_VERSION = 1


def send_msg(sock, data: bytes):
    """Send a length-prefixed binary message over TCP."""
    length = len(data)
    header = struct.pack("!I", length)
    sock.sendall(header + data)


def recv_exact(sock, n: int) -> bytes:
    """Receive exactly n bytes or raise if the socket closes early."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data


def recv_msg(sock) -> bytes:
    """Receive one full length-prefixed message."""
    header = recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length == 0:
        return b""
    return recv_exact(sock, length)


def send_json(sock, payload: dict):
    """Serialize a dictionary as JSON and send it as one framed message."""
    data = json.dumps(payload).encode("utf-8")
    send_msg(sock, data)


def recv_json(sock) -> dict:
    """Receive one framed JSON message and decode it into a dictionary."""
    data = recv_msg(sock)
    if not data:
        return {}
    return json.loads(data.decode("utf-8"))


def build_request(action: str, **fields) -> dict:
    """Build a protocol request with the required metadata envelope."""
    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": uuid.uuid4().hex,
        "action": action,
    }
    payload.update(fields)
    return payload


def build_response(status: str = "ok", request_id: Optional[str] = None, **fields) -> dict:
    """Build a protocol response with consistent metadata fields."""
    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "status": status,
    }
    if request_id is not None:
        payload["request_id"] = request_id
    payload.update(fields)
    return payload


def error_response(error_code: str, message: str, request_id: Optional[str] = None) -> dict:
    """Build a consistent error payload."""
    return build_response(
        status="error",
        request_id=request_id,
        error_code=error_code,
        message=message,
    )


def send_raw_file(sock, fileobj, size: int, chunk_size: int = 65536) -> None:
    """Stream raw file bytes after metadata has already been exchanged."""
    remaining = size
    while remaining > 0:
        chunk = fileobj.read(min(chunk_size, remaining))
        if not chunk:
            break
        sock.sendall(chunk)
        remaining -= len(chunk)

def recv_raw_file(sock, fileobj, size: int, chunk_size: int = 65536, hasher=None) -> None:
    """Receive raw file bytes and optionally update a hash while writing them."""
    remaining = size
    while remaining > 0:
        chunk = sock.recv(min(chunk_size, remaining))
        if not chunk:
            raise ConnectionError("Socket closed during file transfer")
        if hasher is not None:
            hasher.update(chunk)
        fileobj.write(chunk)
        remaining -= len(chunk)
