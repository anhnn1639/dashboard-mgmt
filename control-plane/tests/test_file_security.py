import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag

from app.file_security import MalwareDetected, decrypt_file, decrypt_file_chunk, encrypt_file, encrypt_file_chunk, normalize_upload_name, scan_file_with_clamav, scan_with_clamav


TEST_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="


class FileSecurityTests(unittest.TestCase):
    def test_filename_rejects_traversal_and_windows_devices(self):
        self.assertEqual(normalize_upload_name("security-update.rpm"), "security-update.rpm")
        for value in ("../evil.exe", "folder/file.txt", "CON", "payload?.exe", "file. "):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_upload_name(value)

    def test_encrypted_file_is_bound_to_server_and_hash(self):
        content = b"approved configuration payload"
        digest = "c" * 64
        encrypted, nonce = encrypt_file(content, "transfer-1", "server-1", digest, TEST_KEY)
        self.assertNotIn(content, encrypted)
        self.assertEqual(decrypt_file(encrypted, nonce, "transfer-1", "server-1", digest, TEST_KEY), content)
        with self.assertRaises(InvalidTag):
            decrypt_file(encrypted, nonce, "transfer-1", "server-2", digest, TEST_KEY)

    def test_encrypted_chunk_is_bound_to_sequence_and_size(self):
        content = b"chunked approved payload"
        digest = "d" * 64
        encrypted, nonce = encrypt_file_chunk(content, "transfer-2", "server-1", digest, 3, TEST_KEY)
        self.assertEqual(decrypt_file_chunk(encrypted, nonce, "transfer-2", "server-1", digest, 3, len(content), TEST_KEY), content)
        with self.assertRaises(InvalidTag):
            decrypt_file_chunk(encrypted, nonce, "transfer-2", "server-1", digest, 4, len(content), TEST_KEY)

    def test_clamav_instream_clean_and_detected_responses(self):
        self.assertTrue(self._scan_reply(b"stream: OK\0").endswith(" OK"))
        with self.assertRaisesRegex(MalwareDetected, "Eicar-Test-Signature"):
            self._scan_reply(b"stream: Eicar-Test-Signature FOUND\0")

    def test_clamav_file_stream_uses_same_protocol(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approved.bin"
            path.write_bytes(b"streamed payload")
            self.assertTrue(self._scan_reply(b"stream: OK\0", path).endswith(" OK"))

    @staticmethod
    def _scan_reply(reply: bytes, path: Path | None = None) -> str:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve() -> None:
            connection, _ = listener.accept()
            with connection:
                command = b""
                while not command.endswith(b"\0"):
                    command += connection.recv(1)
                if command != b"zINSTREAM\0":
                    return
                while True:
                    length = struct.unpack(">I", connection.recv(4))[0]
                    if length == 0:
                        break
                    remaining = length
                    while remaining:
                        remaining -= len(connection.recv(remaining))
                connection.sendall(reply)
            listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            return scan_file_with_clamav(path, "127.0.0.1", port, 3) if path else scan_with_clamav(b"test payload", "127.0.0.1", port, 3)
        finally:
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
