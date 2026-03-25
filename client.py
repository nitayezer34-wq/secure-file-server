"""Interactive CLI client for the secure TCP file server."""

import getpass
import hashlib
import os
import socket
import ssl
import string
import sys

from config import CA_CERT_PATH, TLS_ENABLED, get_env, load_dotenv
from protocol import recv_json, recv_raw_file, send_json, send_raw_file

load_dotenv()

MAX_FILE_SIZE = get_env("MAX_FILE_SIZE", 10 * 1024 * 1024, int)
SERVER_HOST = get_env("SERVER_HOST", "127.0.0.1", str)
SERVER_PORT = get_env("SERVER_PORT", 9000, int)
SOCKET_TIMEOUT_SECONDS = get_env("SOCKET_TIMEOUT_SECONDS", 30, int)


def compute_sha256(path: str) -> str:
    """Compute the SHA-256 checksum of a local file before upload."""
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def print_connection_help() -> None:
    """Print actionable guidance when the client cannot reach the server."""
    print(f"Could not connect to server at {SERVER_HOST}:{SERVER_PORT}.")
    print("What to do:")
    print("1. Start the server with: python3 server.py")
    print("2. Make sure SERVER_HOST and SERVER_PORT match in your .env")
    print("3. If the server is already running, check that the port is not blocked or changed")


def main():
    """Run the interactive client loop and dispatch user commands to the server."""
    token = None

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(SOCKET_TIMEOUT_SECONDS)
    if TLS_ENABLED:
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.load_verify_locations(cafile=CA_CERT_PATH)
        sock = ssl_context.wrap_socket(raw_sock, server_hostname="localhost")
    else:
        sock = raw_sock

    with sock:
        try:
            sock.connect((SERVER_HOST, SERVER_PORT))
        except ConnectionRefusedError:
            print_connection_help()
            sys.exit(1)
        except ssl.SSLError as exc:
            print(f"TLS error while connecting to {SERVER_HOST}:{SERVER_PORT}: {exc}")
            print("Check TLS_ENABLED, the server certificate, and server_hostname.")
            sys.exit(1)
        except OSError as exc:
            print(f"Network error while connecting to {SERVER_HOST}:{SERVER_PORT}: {exc}")
            print("Check your .env values and verify the server is running.")
            sys.exit(1)

        mode = "TLS" if TLS_ENABLED else "plain TCP"
        print(f"Connected to server at {SERVER_HOST}:{SERVER_PORT} ({mode})")

        try:
            while True:
                action = input("Command (register/login/list/upload/download/logout/quit): ").strip().lower()
                if action in {"quit", "exit"}:
                    break
                if action in {"register", "login"}:
                    # Registration and login share the same prompt and request shape.
                    username = input("Username: ").strip()
                    password = getpass.getpass("Password: ")
                    send_json(sock, {"action": action, "username": username, "password": password})
                    reply = recv_json(sock)
                    print(reply.get("message", reply))
                    if action == "login" and reply.get("status") == "ok":
                        token = reply.get("token")
                    continue
                if action == "logout":
                    send_json(sock, {"action": "logout", "token": token})
                    reply = recv_json(sock)
                    print(reply.get("message", reply))
                    if reply.get("status") == "ok":
                        token = None
                    continue
                if action == "list":
                    send_json(sock, {"action": "list", "token": token})
                    reply = recv_json(sock)
                    if reply.get("status") == "ok":
                        print("Files:", reply.get("files", []))
                    else:
                        print(reply.get("message", reply))
                    continue
                if action == "upload":
                    if not token:
                        print("Not logged in. Run login first.")
                        continue
                    path = input("Local file path: ").strip()
                    if not os.path.isfile(path):
                        print("File not found. Enter a valid local path.")
                        continue
                    size = os.path.getsize(path)
                    if size > MAX_FILE_SIZE:
                        print(f"File too large. Max allowed size is {MAX_FILE_SIZE} bytes.")
                        continue
                    filename = os.path.basename(path)
                    sha256 = compute_sha256(path)
                    # The server validates size and hash before committing the file.
                    send_json(
                        sock,
                        {
                            "action": "upload",
                            "token": token,
                            "filename": filename,
                            "size": size,
                            "sha256": sha256,
                        },
                    )
                    ready = recv_json(sock)
                    if ready.get("status") != "ok":
                        print(ready.get("message", ready))
                        continue
                    with open(path, "rb") as handle:
                        send_raw_file(sock, handle, size)
                    reply = recv_json(sock)
                    print(reply.get("message", reply))
                    continue
                if action == "download":
                    if not token:
                        print("Not logged in. Run login first.")
                        continue
                    filename = input("Remote filename: ").strip()
                    save_path = input("Save as (leave empty for same name): ").strip()
                    if not save_path:
                        save_path = filename
                    send_json(sock, {"action": "download", "token": token, "filename": filename})
                    reply = recv_json(sock)
                    if reply.get("status") != "ok":
                        print(reply.get("message", reply))
                        continue
                    # Download is verified locally again to catch corruption in transit.
                    size = reply.get("size")
                    expected_hash = reply.get("sha256", "")
                    if not isinstance(size, int) or size < 0:
                        print("Invalid size from server.")
                        continue
                    if size > MAX_FILE_SIZE:
                        print(f"File too large. Max allowed size is {MAX_FILE_SIZE} bytes.")
                        return
                    if not (
                        isinstance(expected_hash, str)
                        and len(expected_hash) == 64
                        and all(c in string.hexdigits for c in expected_hash)
                    ):
                        print("Invalid sha256 from server.")
                        continue
                    expected_hash = expected_hash.lower()
                    hasher = hashlib.sha256()
                    with open(save_path, "wb") as handle:
                        recv_raw_file(sock, handle, size, hasher=hasher)
                    received_hash = hasher.hexdigest()
                    if received_hash != expected_hash:
                        try:
                            os.remove(save_path)
                        except OSError:
                            pass
                        print("Download failed: sha256 mismatch.")
                        continue
                    print(f"Downloaded and verified: {save_path}")
                    continue
                print("Unknown command. Use: register, login, list, upload, download, logout, quit.")
        except (ConnectionError, OSError, socket.timeout) as exc:
            print(f"Connection lost: {exc}")
            print("Restart the server if needed, then run the client again.")
            sys.exit(1)


if __name__ == "__main__":
    main()
