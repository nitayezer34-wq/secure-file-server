"""Configuration helpers for loading environment variables and .env values."""

import os
from pathlib import Path
from typing import Callable, TypeVar

T = TypeVar("T")
PROJECT_ROOT = Path(__file__).resolve().parent


def load_dotenv(path: str = ".env") -> None:
    """Load simple KEY=VALUE pairs from a local .env file into os.environ."""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'").strip('"')
            if key:
                os.environ.setdefault(key, value)


def get_env(name: str, default: T, caster: Callable[[str], T]) -> T:
    """Read an environment variable and cast it, or return the default value."""
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return caster(value)
    except (TypeError, ValueError):
        return default


def _to_bool(value: str) -> bool:
    """Parse common truthy values from environment variables."""
    return value.strip().lower() in {"1", "true", "yes", "on"}


load_dotenv()

TLS_ENABLED = get_env("TLS_ENABLED", False, _to_bool)
SERVER_CERT_PATH = get_env("SERVER_CERT_PATH", "certs/server.crt", str)
SERVER_KEY_PATH = get_env("SERVER_KEY_PATH", "certs/server.key", str)
CA_CERT_PATH = get_env("CA_CERT_PATH", "certs/server.crt", str)


def _resolve_path(path: str) -> Path:
    """Resolve a configured path relative to the project root when needed."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    return candidate.resolve()


def validate_server_tls_config() -> tuple[str, str]:
    """Validate TLS server paths and return resolved certificate and key paths."""
    cert_path = _resolve_path(SERVER_CERT_PATH)
    key_path = _resolve_path(SERVER_KEY_PATH)

    missing = []
    if not cert_path.is_file():
        missing.append(f"certificate file not found: {cert_path}")
    if not key_path.is_file():
        missing.append(f"private key file not found: {key_path}")
    if missing:
        raise RuntimeError(
            "TLS is enabled, but the server TLS configuration is incomplete:\n- "
            + "\n- ".join(missing)
        )

    return str(cert_path), str(key_path)


def validate_client_tls_config() -> str:
    """Validate the CA certificate path and return the resolved path."""
    ca_cert_path = _resolve_path(CA_CERT_PATH)
    if not ca_cert_path.is_file():
        raise RuntimeError(
            "TLS is enabled, but the client CA certificate was not found: "
            f"{ca_cert_path}"
        )
    return str(ca_cert_path)
