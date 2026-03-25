import hashlib
import os
import tempfile
import time
import unittest
from unittest.mock import patch

import server


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
    def test_is_safe_filename_accepts_simple_names(self):
        self.assertTrue(server.is_safe_filename("notes.txt"))
        self.assertTrue(server.is_safe_filename("file-01.log"))

    def test_is_safe_filename_rejects_dangerous_names(self):
        self.assertFalse(server.is_safe_filename("../secret.txt"))
        self.assertFalse(server.is_safe_filename("folder/file.txt"))
        self.assertFalse(server.is_safe_filename(r"..\\file.txt"))
        self.assertFalse(server.is_safe_filename(""))

    def test_hash_password_is_stable_for_same_salt(self):
        salt = bytes.fromhex("00112233445566778899aabbccddeeff")
        first = server.hash_password("correct horse battery staple", salt)
        second = server.hash_password("correct horse battery staple", salt)
        other = server.hash_password("different", salt)
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)

    def test_expired_session_returns_none_and_is_removed(self):
        sessions = {
            "expired-token": {
                "username": "alice",
                "expires_at": time.time() - 5,
            }
        }
        username = server.get_username_from_token({"token": "expired-token"}, sessions)
        self.assertIsNone(username)
        self.assertNotIn("expired-token", sessions)

    def test_record_failed_login_triggers_lockout_at_threshold(self):
        attempts = {}
        with patch.object(server, "LOCKOUT_THRESHOLD", 3), patch.object(
            server, "LOCKOUT_WINDOW_SECONDS", 60
        ), patch.object(server, "LOCKOUT_DURATION_SECONDS", 30):
            with patch("server.time.time", side_effect=[1000.0, 1001.0, 1002.0]):
                server.record_failed_login("alice", attempts)
                server.record_failed_login("alice", attempts)
                server.record_failed_login("alice", attempts)

        self.assertIn("alice", attempts)
        self.assertEqual(attempts["alice"]["count"], 3)
        self.assertGreater(attempts["alice"]["locked_until"], 1002.0)
        with patch("server.time.time", return_value=1003.0):
            self.assertEqual(
                server.check_lockout("alice", attempts),
                "Too many failed attempts. Try again later.",
            )

    def test_check_lockout_clears_expired_entry(self):
        attempts = {
            "alice": {
                "count": 5,
                "first_fail": time.time() - 100,
                "locked_until": time.time() - 1,
            }
        }
        self.assertIsNone(server.check_lockout("alice", attempts))
        self.assertNotIn("alice", attempts)

    def test_upload_sha256_mismatch_rejects_file_and_cleans_temp_file(self):
        content = b"hello world"
        wrong_hash = hashlib.sha256(b"different").hexdigest()
        payload = {
            "filename": "demo.txt",
            "size": len(content),
            "sha256": wrong_hash,
        }
        sock = FakeSocket(incoming=content)
        file_locks = server.FileLockRegistry()

        with tempfile.TemporaryDirectory() as temp_dir, patch.object(server, "STORAGE_DIR", temp_dir):
            response = server.handle_upload(payload, "alice", sock, file_locks)
            final_path = os.path.join(temp_dir, "alice", "demo.txt")
            temp_path = f"{final_path}.part"

        self.assertEqual(response["status"], "error")
        self.assertEqual(response["message"], "sha256 mismatch")
        self.assertFalse(os.path.exists(final_path))
        self.assertFalse(os.path.exists(temp_path))
        self.assertGreater(len(sock.sent), 0)


if __name__ == "__main__":
    unittest.main()
