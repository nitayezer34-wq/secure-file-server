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


class ProtocolTests(unittest.TestCase):
    def test_recv_exact_collects_multiple_chunks(self):
        sock = FakeRecvSocket([b"ab", b"cd", b"ef"])
        self.assertEqual(protocol.recv_exact(sock, 6), b"abcdef")

    def test_recv_exact_raises_on_early_close(self):
        sock = FakeRecvSocket([b"ab"])
        with self.assertRaises(ConnectionError):
            protocol.recv_exact(sock, 4)


if __name__ == "__main__":
    unittest.main()
