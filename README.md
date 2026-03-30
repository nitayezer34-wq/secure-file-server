# Secure File Server

A backend/systems project focused on low-level TCP protocol design, secure authentication, and concurrent file handling.

Custom application-layer protocol over raw TCP using length-prefixed JSON framing.  
Thread-per-client server with authenticated multi-user access and per-user storage isolation.  
Optional TLS with fail-fast validation, `.env`-driven configuration, and Docker/Compose deployment.


## Technical Highlights

### Networking
- Custom application-layer protocol over raw TCP
- 4-byte length-prefixed JSON framing
- Raw file streaming after metadata exchange
- Exact-byte reads for TCP stream correctness

### Security
- PBKDF2-HMAC-SHA256 password hashing with per-user salt
- Constant-time password verification
- Login lockout protection
- TLS support with fail-fast validation
- SHA-256 verification on upload and download
- Per-user storage isolation
- Filename and path validation
- Atomic file replacement on upload

### Concurrency
- Thread-per-client server model
- Shared session state protected by locks
- Per-file locking for concurrent file access

### Deployment
- `.env`-driven configuration
- Automated bootstrap with `setup.py`
- Dockerized server workflow
- `docker compose` support
- Persistent runtime volumes
- Non-root container execution

### Testing
- Unit tests for protocol handling, authentication flows, and core server logic

## Quick Start

### Local run
```bash
python3 setup.py init
python3 server.py
python3 client.py
```

### Docker Compose
```bash
python3 setup.py init
docker compose up --build
```

### Enable TLS for local testing
```bash
python3 setup.py createcrt --name server --days 365
```

Then update `.env`:

```env
TLS_ENABLED=true
SERVER_CERT_PATH=certs/server.crt
SERVER_KEY_PATH=certs/server.key
CA_CERT_PATH=certs/server.crt
```

## Project Structure
```text
.
├── auth.py
├── client.py
├── config.py
├── protocol.py
├── server.py
├── setup.py
├── storage.py
├── tests/
├── certs/
├── storage/
├── users.json
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## Architecture Overview

### Server
`server.py` runs a multi-user TCP server using a thread-per-client model. It accepts client connections, performs request routing, manages sessions, applies authentication checks, and delegates file operations.

### Client
`client.py` is an interactive CLI client that supports register, login, list, upload, download, logout, and optional TLS.

### Protocol Layer
`protocol.py` implements the wire protocol primitives:
- 4-byte big-endian message length prefix for JSON messages
- exact byte reads for TCP stream correctness
- raw file streaming after metadata exchange

### Authentication Layer
`auth.py` handles:
- password hashing with `PBKDF2-HMAC-SHA256`
- constant-time hash comparison
- session token issuance and expiration
- failed-login tracking and temporary lockout

### Storage Layer
`storage.py` handles:
- per-user directory layout under `storage/<username>/`
- username and filename validation
- upload/download workflows
- temporary file writes and atomic replacement
- in-process per-file locking

### Configuration Layer
`config.py` loads configuration from `.env` and environment variables, and validates TLS paths when TLS is enabled.

## Protocol Overview
TCP is a byte stream, not a message-oriented transport. This project therefore implements explicit framing rather than assuming one `send()` maps to one `recv()`.

### Framing strategy
Every JSON control message is sent as:

```text
+--------------------+----------------------+
| 4-byte length      | JSON payload bytes   |
+--------------------+----------------------+
```

This avoids boundary ambiguity and makes the protocol robust over a raw socket connection.

### Message flow
1. Client sends framed JSON metadata.
2. Server validates the request and authentication state.
3. If the operation is a file transfer, metadata is exchanged first.
4. Raw file bytes are streamed only after both sides agree on size and transfer state.

### Supported actions
| Action | Request | Response | Extra bytes |
| --- | --- | --- | --- |
| `register` | username + password | success/error JSON | None |
| `login` | username + password | success/error JSON, optional token | None |
| `logout` | token | success/error JSON | None |
| `list` | token | file list JSON | None |
| `upload` | token + filename + size + sha256 | ready/error JSON | client then sends raw file bytes |
| `download` | token + filename | metadata/error JSON | server then sends raw file bytes |

## Request Flows

### Register
1. Client sends framed JSON with `action=register`, `username`, and `password`.
2. Server validates the username and checks whether the user already exists.
3. Server creates a random salt, hashes the password, stores the result in `users.json`, and creates the user storage directory.
4. Server returns a JSON success or error response.

### Login
1. Client sends framed JSON credentials.
2. Server checks lockout state.
3. Server verifies the password using `PBKDF2-HMAC-SHA256` and constant-time comparison.
4. Server issues a session token with expiration on success.
5. Server returns the token in the response.

### Upload
1. Client computes the local file SHA-256.
2. Client sends metadata: filename, size, sha256, and token.
3. Server validates authentication, filename, declared size, and digest format.
4. Server replies with `READY` if the transfer may proceed.
5. Client streams raw file bytes.
6. Server writes to a temporary `.part` file while hashing the incoming content.
7. Server verifies the received SHA-256 and atomically replaces the final file only on success.

### Download
1. Client sends a framed JSON request with `action=download`, token, and filename.
2. Server validates authentication and file existence.
3. Server computes file size and SHA-256.
4. Server sends metadata containing `size` and `sha256`.
5. Server streams raw file bytes.
6. Client writes the file locally while recomputing SHA-256.
7. Client deletes the local output if the final hash does not match.

## Security

### Authentication and Session Handling
- passwords are hashed with `PBKDF2-HMAC-SHA256`
- each user gets a unique random salt
- password verification uses constant-time comparison
- login failures are tracked and can trigger temporary lockout
- session tokens are issued after login and expire after a configurable TTL

### File Safety
- usernames and filenames are validated against traversal and ambiguous path input
- each user is restricted to their own storage directory
- uploads are written to a temporary file first
- successful uploads use atomic replace to reduce corruption risk
- per-file locks reduce races on concurrent access to the same file

### TLS
TLS is disabled by default but supported explicitly.

When `TLS_ENABLED=true`:
- the server validates that both the configured certificate and private key exist before startup
- the client validates that the configured CA/self-signed certificate exists before connecting
- misconfiguration fails early with a readable error instead of a vague SSL failure later

For local development, `setup.py createcrt` generates a self-signed certificate suitable for `localhost` and `127.0.0.1`.

Security-sensitive paths such as authentication, invalid requests, hash mismatches, and TLS misconfiguration are covered by unit tests.

## Configuration
Configuration is environment-driven through `.env` and standard environment variables.

## Docker

### Image and runtime approach
- official `python:3.12-slim` base image
- cache-friendly Dockerfile order
- non-root runtime user
- persistent bind mounts

### Run with Compose
```bash
python3 setup.py init
docker compose up --build
```

## Testing
```bash
python3 -m unittest discover -s tests -v
```

## Limitations
- no database (JSON-based storage)
- in-memory sessions
- thread-per-client (not high-scale)
- manual TLS lifecycle

## Portfolio Summary
Demonstrates protocol design, concurrency, security, and containerized deployment in a clean, end-to-end backend project.
