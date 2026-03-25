# Secure File Transfer System

Secure Python client-server file transfer over TCP with framed JSON control messages, raw file streaming, per-user isolation, integrity verification, and optional TLS.

## Key Capabilities
- Authenticated upload and download with session tokens and expiration
- PBKDF2 password hashing, login lockout, and safe path handling
- Custom length-prefixed protocol built for TCP stream semantics
- SHA-256 verification for upload and download integrity
- Multithreaded server with per-file locking and environment-based configuration

## How It Works
The CLI client sends framed JSON requests over TCP for control operations such as register, login, list, upload, and download. For file transfers, metadata is exchanged first as JSON, then the file content is streamed as raw bytes. The server authenticates the session, validates the request, and reads or writes files only inside the authenticated user’s storage directory.

## Quick Start
```bash
cp .env.example .env
python3 server.py
python3 client.py
```

## Architecture Overview
The project keeps a straightforward module split:

| File | Responsibility |
| --- | --- |
| `server.py` | Accepts TCP clients, authenticates users, manages sessions, enforces lockout rules, and handles file operations |
| `client.py` | Interactive CLI for register, login, list, upload, download, and logout |
| `protocol.py` | Length-prefix framing, JSON message helpers, and raw file streaming helpers |
| `config.py` | Loads `.env` values and environment variables with type conversion |
| `users.json` | Simple JSON user store with salt and PBKDF2 password hash |
| `storage/` | Per-user file storage root |

The server follows a thread-per-client model. Shared state such as sessions and failed login counters is protected with locks. File writes and reads are guarded by per-path locks to reduce races on the same file.

## Protocol Design
TCP is a byte stream, not a message-based protocol. That means one `send()` call on one side does not guarantee one matching `recv()` call on the other side. To avoid ambiguous boundaries, every JSON message is sent with a 4-byte big-endian length prefix.

Protocol layers:
1. JSON metadata messages are framed with a 4-byte length prefix.
2. File content is streamed as raw bytes only after both sides already know the exact file size from JSON metadata.
3. Upload and download flows combine both forms: framed JSON for control, then raw bytes for file content.

### Length-Prefix Framing
Each JSON message is sent as:

```text
+--------------------+----------------------+
| 4-byte length      | JSON payload bytes   |
+--------------------+----------------------+
```

Example:
- Client serializes `{"action": "list", "token": "..."}` to UTF-8 bytes.
- Client sends 4 bytes containing the payload length.
- Client sends the JSON bytes.
- Server reads exactly 4 bytes, decodes the length, then reads exactly that many bytes.

This is implemented in `protocol.py` via `send_msg()`, `recv_exact()`, `recv_msg()`, `send_json()`, and `recv_json()`.

## Protocol Reference
The following table describes the current request and response shapes used by the implementation.

| Action | Client JSON | Server Response | Extra Bytes |
| --- | --- | --- | --- |
| `register` | `{"action":"register","username":"alice","password":"secret"}` | `{"status":"ok","message":"User registered"}` or error | None |
| `login` | `{"action":"login","username":"alice","password":"secret"}` | `{"status":"ok","message":"Login successful","token":"..."}` or error | None |
| `logout` | `{"action":"logout","token":"..."}` | `{"status":"ok","message":"Logged out"}` or error | None |
| `list` | `{"action":"list","token":"..."}` | `{"status":"ok","files":[...]}` or error | None |
| `upload` metadata | `{"action":"upload","token":"...","filename":"notes.txt","size":123,"sha256":"..."}` | `{"status":"ok","message":"READY"}` or error | If ready, client sends `size` raw file bytes |
| `upload` completion | None | `{"status":"ok","message":"Upload complete"}` or `{"status":"error","message":"sha256 mismatch"}` | None |
| `download` | `{"action":"download","token":"...","filename":"notes.txt"}` | `{"status":"ok","size":123,"sha256":"..."}` or error | If ok, server sends `size` raw file bytes |

## Request/Response Flows

### Register
1. Client sends framed JSON with `action=register`, `username`, and `password`.
2. Server validates the request.
3. Server creates a random salt, derives a PBKDF2-HMAC-SHA256 password hash, stores both in `users.json`, and creates the user storage directory.
4. Server replies with success or error JSON.

Example:

```json
{"action":"register","username":"alice","password":"secret"}
```

```json
{"status":"ok","message":"User registered"}
```

### Login
1. Client sends framed JSON with credentials.
2. Server checks lockout state.
3. Server verifies the PBKDF2 password hash using constant-time comparison.
4. Server creates a random session token with expiration.
5. Server replies with the token on success.

Example:

```json
{"action":"login","username":"alice","password":"secret"}
```

```json
{"status":"ok","message":"Login successful","token":"4b5b..."}
```

### Upload
1. Client computes the local file SHA-256.
2. Client sends framed JSON metadata containing `filename`, `size`, `sha256`, and `token`.
3. Server validates authentication, filename, declared size, and digest format.
4. Server replies with `READY` if the upload may proceed.
5. Client streams raw file bytes.
6. Server writes to a temporary `.part` file while hashing the incoming bytes.
7. If the calculated SHA-256 matches the declared value, the server atomically replaces the final file.
8. Server sends a final JSON result.

Metadata:

```json
{"action":"upload","token":"...","filename":"report.pdf","size":2048,"sha256":"abc123..."}
```

Ready response:

```json
{"status":"ok","message":"READY"}
```

Completion response:

```json
{"status":"ok","message":"Upload complete"}
```

### Download
1. Client sends framed JSON with `action=download`, `token`, and `filename`.
2. Server validates authentication and file existence.
3. Server computes file size and SHA-256.
4. Server sends framed JSON metadata with `size` and `sha256`.
5. Server streams raw file bytes.
6. Client writes the file locally while computing its own SHA-256.
7. Client deletes the downloaded file if the hash does not match.

Metadata response:

```json
{"status":"ok","size":2048,"sha256":"abc123..."}
```

## Security Features
- PBKDF2-HMAC-SHA256 password hashing with a unique random salt per user
- Constant-time password comparison using `hmac.compare_digest`
- Session tokens with expiration
- Login lockout after repeated failed attempts within a time window
- Optional TLS support for encrypted transport
- Per-user storage directories
- Safe filename validation to reduce path traversal risk
- Maximum file size enforcement
- SHA-256 integrity verification on upload and download
- Temporary file writes with atomic replace on successful upload
- Per-file locks and shared-state locks for basic thread safety

## Setup
### Requirements
This project uses the Python standard library only. No third-party packages are required.

Recommended version:
- Python 3.9 or newer

### Configuration
Create a local `.env` file from `.env.example` if you want to override defaults.

Important settings:
- `SERVER_HOST`
- `SERVER_PORT`
- `TLS_ENABLED`
- `USERS_FILE`
- `STORAGE_DIR`
- `LOG_FILE`
- `MAX_FILE_SIZE`
- `SESSION_TTL_SECONDS`
- `LOCKOUT_THRESHOLD`
- `LOCKOUT_WINDOW_SECONDS`
- `LOCKOUT_DURATION_SECONDS`
- `PASSWORD_ITERATIONS`
- `SOCKET_TIMEOUT_SECONDS`
- `SERVER_CERT_PATH`
- `SERVER_KEY_PATH`
- `CA_CERT_PATH`

### Run the Server

```bash
python3 server.py
```

### Run the Client

```bash
python3 client.py
```

### Run the Tests

```bash
python3 -m unittest discover -s tests -v
```

## TLS Notes
TLS is disabled by default. To enable it:
1. Set `TLS_ENABLED=true` in `.env`.
2. Provide a server certificate and private key at the configured paths.
3. Point the client `CA_CERT_PATH` to the certificate authority or self-signed certificate you trust for testing.

For a student portfolio project, self-signed certificates are acceptable for local testing, but they are not equivalent to a production PKI deployment.

## Limitations
- User data is stored in a JSON file rather than a database
- Session state is held in memory, so it is lost when the server restarts
- The protocol is intentionally simple and does not support resumable transfers
- The server uses a thread-per-client model, which is fine for small-scale workloads but not optimized for high concurrency
- There is no role model, audit backend, or advanced access control
- TLS certificate lifecycle management is manual

## Future Improvements
- Add structured protocol versioning
- Add automated certificate generation instructions for local development
- Separate server logic into smaller modules as the project grows
- Add integration tests for full client-server flows
- Add configurable storage quotas per user
- Add request IDs or richer logging context for troubleshooting

## Why This Project Works Well as a Portfolio Piece
This repository demonstrates practical networking and security concepts without unnecessary complexity:
- Socket programming over TCP
- Message framing over a byte stream
- Authentication and session management
- Secure password storage
- File transfer and integrity verification
- Thread safety and concurrent client handling
- Basic operational configuration through environment variables
