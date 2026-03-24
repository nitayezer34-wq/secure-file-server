"""Configuration helpers for loading environment variables and .env values."""

import os
from typing import Callable, TypeVar

T = TypeVar("T")


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
