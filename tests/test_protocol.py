import unittest

import protocol


class FakeRecvSocket:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    def recv(self, n):
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if len(chunk) <= n:
            return chunk
        self._chunks.insert(0, chunk[n:])
        return chunk[:n]


class LoopbackSocket:
    def __init__(self):
        self.buffer = bytearray()

    def sendall(self, data):
        self.buffer.extend(data)

    def recv(self, n):
        if not self.buffer:
            return b""
        chunk = bytes(self.buffer[:n])
        del self.buffer[:n]
        return chunk


class ProtocolTests(unittest.TestCase):
    def test_recv_exact_collects_multiple_chunks(self):
        sock = FakeRecvSocket([b"ab", b"cd", b"ef"])
        self.assertEqual(protocol.recv_exact(sock, 6), b"abcdef")

    def test_recv_exact_raises_on_early_close(self):
        sock = FakeRecvSocket([b"ab"])
        with self.assertRaises(ConnectionError):
            protocol.recv_exact(sock, 4)

    def test_send_json_and_recv_json_roundtrip(self):
        sock = LoopbackSocket()
        first = {"action": "list", "token": "abc"}
        second = {"status": "ok", "files": ["a.txt", "b.txt"]}
        protocol.send_json(sock, first)
        protocol.send_json(sock, second)
        self.assertEqual(protocol.recv_json(sock), first)
        self.assertEqual(protocol.recv_json(sock), second)

    def test_build_request_adds_protocol_metadata(self):
        request = protocol.build_request("list", token="abc")
        self.assertEqual(request["protocol_version"], protocol.PROTOCOL_VERSION)
        self.assertEqual(request["action"], "list")
        self.assertEqual(request["token"], "abc")
        self.assertIn("request_id", request)

    def test_error_response_is_consistent(self):
        response = protocol.error_response("INVALID_REQUEST", "Bad request", request_id="req-1")
        self.assertEqual(
            response,
            {
                "protocol_version": protocol.PROTOCOL_VERSION,
                "status": "error",
                "request_id": "req-1",
                "error_code": "INVALID_REQUEST",
                "message": "Bad request",
            },
        )


if __name__ == "__main__":
    unittest.main()
