import hashlib
import os
import tempfile
import time
import unittest
from unittest.mock import patch

import auth
import config
import protocol
import server
import storage


class FakeSocket:
    def __init__(self, incoming=b""):
        self._incoming = incoming
        self.sent = bytearray()

    def recv(self, n):
        if not self._incoming:
            return b""
        chunk = self._incoming[:n]
        self._incoming = self._incoming[n:]
        return chunk

    def sendall(self, data):
        self.sent.extend(data)


class ServerLogicTests(unittest.TestCase):
    def make_request(self, action, **fields):
        return protocol.build_request(action, **fields)

    def test_is_safe_filename_accepts_simple_names(self):
        self.assertTrue(storage.is_safe_filename("notes.txt"))
        self.assertTrue(storage.is_safe_filename("file-01.log"))

    def test_is_safe_filename_rejects_dangerous_names(self):
        self.assertFalse(storage.is_safe_filename("../secret.txt"))
        self.assertFalse(storage.is_safe_filename("folder/file.txt"))
        self.assertFalse(storage.is_safe_filename(r"..\\file.txt"))
        self.assertFalse(storage.is_safe_filename(""))

    def test_is_safe_username_rejects_dangerous_names(self):
        self.assertFalse(storage.is_safe_username(""))
        self.assertFalse(storage.is_safe_username("../alice"))
        self.assertFalse(storage.is_safe_username("alice/admin"))
        self.assertFalse(storage.is_safe_username(r"alice\admin"))
        self.assertFalse(storage.is_safe_username("alice..test"))
        self.assertFalse(storage.is_safe_username("alice!"))

    def test_hash_password_is_stable_for_same_salt(self):
        salt = bytes.fromhex("00112233445566778899aabbccddeeff")
        first = auth.hash_password("correct horse battery staple", salt)
        second = auth.hash_password("correct horse battery staple", salt)
        other = auth.hash_password("different", salt)
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)

    def test_expired_session_returns_none_and_is_removed(self):
        sessions = {
            "expired-token": {
                "username": "alice",
                "expires_at": time.time() - 5,
            }
        }
        username = auth.get_username_from_token({"token": "expired-token"}, sessions)
        self.assertIsNone(username)
        self.assertNotIn("expired-token", sessions)

    def test_record_failed_login_triggers_lockout_at_threshold(self):
        login_failures = {}
        with patch.object(auth, "LOCKOUT_THRESHOLD", 3), patch.object(
            auth, "LOCKOUT_WINDOW_SECONDS", 60
        ), patch.object(auth, "LOCKOUT_DURATION_SECONDS", 30):
            with patch("auth.time.time", side_effect=[1000.0, 1001.0, 1002.0]):
                auth.record_failed_login("alice", login_failures)
                auth.record_failed_login("alice", login_failures)
                auth.record_failed_login("alice", login_failures)

        self.assertIn("alice", login_failures)
        self.assertEqual(login_failures["alice"]["count"], 3)
        self.assertGreater(login_failures["alice"]["locked_until"], 1002.0)
        with patch("auth.time.time", return_value=1003.0):
            self.assertEqual(
                auth.check_lockout("alice", login_failures),
                "Too many failed attempts. Try again later.",
            )

    def test_handle_login_success_returns_token(self):
        salt = bytes.fromhex("00112233445566778899aabbccddeeff")
        users = {
            "users": {
                "alice": {
                    "salt": salt.hex(),
                    "password_hash": auth.hash_password("secret", salt),
                }
            }
        }
        sessions = {}
        login_failures = {}
        response = auth.handle_login(
            {"username": "alice", "password": "secret"},
            users,
            sessions,
            login_failures,
            ("127.0.0.1", 12345),
        )
        self.assertEqual(response["status"], "ok")
        self.assertIn("token", response)
        self.assertEqual(sessions[response["token"]]["username"], "alice")

    def test_handle_login_returns_lockout_message_for_locked_user(self):
        salt = bytes.fromhex("00112233445566778899aabbccddeeff")
        users = {
            "users": {
                "alice": {
                    "salt": salt.hex(),
                    "password_hash": auth.hash_password("secret", salt),
                }
            }
        }
        sessions = {}
        login_failures = {
            "alice": {
                "count": 5,
                "first_fail": time.time(),
                "locked_until": time.time() + 60,
            }
        }
        response = auth.handle_login(
            {"username": "alice", "password": "secret"},
            users,
            sessions,
            login_failures,
            ("127.0.0.1", 12345),
        )
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["message"], "Too many failed attempts. Try again later.")

    def test_check_lockout_clears_expired_entry(self):
        login_failures = {
            "alice": {
                "count": 5,
                "first_fail": time.time() - 100,
                "locked_until": time.time() - 1,
            }
        }
        self.assertIsNone(auth.check_lockout("alice", login_failures))
        self.assertNotIn("alice", login_failures)

    def test_upload_sha256_mismatch_rejects_file_and_cleans_temp_file(self):
        content = b"hello world"
        wrong_hash = hashlib.sha256(b"different").hexdigest()
        payload = {
            "filename": "demo.txt",
            "size": len(content),
            "sha256": wrong_hash,
        }
        sock = FakeSocket(incoming=content)
        file_locks = storage.FileLockRegistry()

        with tempfile.TemporaryDirectory() as temp_dir, patch.object(storage, "STORAGE_DIR", temp_dir):
            response = storage.handle_upload(payload, "alice", sock, file_locks)
            final_path = os.path.join(temp_dir, "alice", "demo.txt")
            temp_path = f"{final_path}.part"

        self.assertEqual(response["status"], "error")
        self.assertEqual(response["message"], "sha256 mismatch")
        self.assertFalse(os.path.exists(final_path))
        self.assertFalse(os.path.exists(temp_path))
        self.assertGreater(len(sock.sent), 0)

    def test_register_rejects_unsafe_username(self):
        users = {"users": {}}
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(server, "STORAGE_DIR", temp_dir), patch.object(
            storage, "STORAGE_DIR", temp_dir
        ):
            response = server.handle_register({"username": "../alice", "password": "secret"}, users)
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["message"], "Invalid username")
        self.assertEqual(users, {"users": {}})

    def test_protected_actions_reject_invalid_token(self):
        state = server.ServerState()
        state.users = {"users": {}}
        state.sessions = {}
        file_locks = storage.FileLockRegistry()
        conn = FakeSocket()
        addr = ("127.0.0.1", 9000)

        for action in ("list", "upload", "download"):
            payload = self.make_request(action, token="invalid", filename="demo.txt", size=10, sha256="a" * 64)
            if action == "list":
                payload = self.make_request(action, token="invalid")
            if action == "download":
                payload = self.make_request(action, token="invalid", filename="demo.txt")
            response = server.process_request(payload, addr, state, conn, file_locks)
            self.assertEqual(response["status"], "error")
            self.assertEqual(response["error_code"], "AUTH_REQUIRED")
            self.assertEqual(response["message"], "Not authenticated")

    def test_process_request_rejects_missing_request_id(self):
        state = server.ServerState()
        state.users = {"users": {}}
        file_locks = storage.FileLockRegistry()
        conn = FakeSocket()
        addr = ("127.0.0.1", 9000)
        payload = {"protocol_version": protocol.PROTOCOL_VERSION, "action": "list", "token": "abc"}
        response = server.process_request(payload, addr, state, conn, file_locks)
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["error_code"], "INVALID_REQUEST")

    def test_process_request_rejects_unsupported_protocol_version(self):
        state = server.ServerState()
        state.users = {"users": {}}
        file_locks = storage.FileLockRegistry()
        conn = FakeSocket()
        addr = ("127.0.0.1", 9000)
        payload = {"protocol_version": 999, "request_id": "req-1", "action": "list", "token": "abc"}
        response = server.process_request(payload, addr, state, conn, file_locks)
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["error_code"], "UNSUPPORTED_PROTOCOL_VERSION")

    def test_download_missing_file_returns_error(self):
        sock = FakeSocket()
        file_locks = storage.FileLockRegistry()
        payload = {"filename": "missing.txt"}
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(storage, "STORAGE_DIR", temp_dir):
            response = storage.handle_download(payload, "alice", sock, file_locks, request_id="req-1")
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["message"], "File not found")

    def test_validate_server_tls_config_rejects_missing_files(self):
        with patch.object(config, "SERVER_CERT_PATH", "certs/missing.crt"), patch.object(
            config, "SERVER_KEY_PATH", "certs/missing.key"
        ):
            with self.assertRaises(RuntimeError):
                config.validate_server_tls_config()

    def test_validate_client_tls_config_rejects_missing_file(self):
        with patch.object(config, "CA_CERT_PATH", "certs/missing.crt"):
            with self.assertRaises(RuntimeError):
                config.validate_client_tls_config()


if __name__ == "__main__":
    unittest.main()
