"""Project bootstrap utility for local development and TLS test certificates."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
CERTS_DIR = PROJECT_ROOT / "certs"
STORAGE_DIR = PROJECT_ROOT / "storage"
USERS_FILE = PROJECT_ROOT / "users.json"
ENV_FILE = PROJECT_ROOT / ".env"
ENV_EXAMPLE_FILE = PROJECT_ROOT / ".env.example"


def ensure_directory(path: Path) -> bool:
    """Create a directory if it does not exist."""
    if path.exists():
        return False
    path.mkdir(parents=True, exist_ok=True)
    return True


def ensure_users_file(path: Path) -> bool:
    """Create the user database with valid JSON if it does not exist."""
    if path.exists():
        return False
    path.write_text(json.dumps({"users": {}}, indent=2) + "\n", encoding="utf-8")
    return True


def ensure_env_file(env_path: Path, example_path: Path) -> str:
    """Create .env from .env.example when available and missing."""
    if env_path.exists():
        return "exists"
    if not example_path.exists():
        return "missing_example"
    shutil.copyfile(example_path, env_path)
    return "created"


def run_init(copy_env: bool = True) -> int:
    """Create the expected local development directories and files."""
    created_certs = ensure_directory(CERTS_DIR)
    created_storage = ensure_directory(STORAGE_DIR)
    created_users = ensure_users_file(USERS_FILE)
    env_result = ensure_env_file(ENV_FILE, ENV_EXAMPLE_FILE) if copy_env else "skipped"

    print("Initialization complete.")
    print(f"- certs/: {'created' if created_certs else 'already exists'}")
    print(f"- storage/: {'created' if created_storage else 'already exists'}")
    print(f"- users.json: {'created' if created_users else 'already exists'}")
    if env_result == "created":
        print("- .env: created from .env.example")
    elif env_result == "exists":
        print("- .env: already exists")
    elif env_result == "missing_example":
        print("- .env: skipped (.env.example not found)")
    else:
        print("- .env: skipped by option")
    return 0


def build_openssl_config() -> str:
    """Build an OpenSSL config that includes SANs for localhost testing."""
    return """
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
""".lstrip()


def generate_self_signed_certificate(name: str, days: int) -> tuple[Path, Path]:
    """Generate a self-signed certificate and private key under certs/."""
    openssl_path = shutil.which("openssl")
    if not openssl_path:
        raise RuntimeError(
            "OpenSSL is required for 'createcrt' but was not found in PATH. "
            "Install OpenSSL and run the command again."
        )

    ensure_directory(CERTS_DIR)
    cert_path = CERTS_DIR / f"{name}.crt"
    key_path = CERTS_DIR / f"{name}.key"

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".cnf", delete=False) as handle:
        config_path = Path(handle.name)
        handle.write(build_openssl_config())

    command = [
        openssl_path,
        "req",
        "-x509",
        "-nodes",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        str(days),
        "-config",
        str(config_path),
        "-extensions",
        "v3_req",
    ]

    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("OpenSSL failed to generate the self-signed certificate.") from exc
    finally:
        config_path.unlink(missing_ok=True)

    return cert_path, key_path


def run_createcrt(name: str, days: int) -> int:
    """Create a local self-signed certificate and private key."""
    if not name:
        raise RuntimeError("Certificate name must not be empty.")
    if days <= 0:
        raise RuntimeError("Certificate validity days must be greater than zero.")

    cert_path, key_path = generate_self_signed_certificate(name=name, days=days)
    print("Self-signed TLS assets created.")
    print(f"- certificate: {cert_path}")
    print(f"- private key: {key_path}")
    print("- subject/SAN: localhost, 127.0.0.1")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser."""
    parser = argparse.ArgumentParser(
        description="Bootstrap local project files and generate TLS test certificates."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init",
        help="Create local folders and files required for development.",
    )
    init_parser.add_argument(
        "--no-env",
        action="store_true",
        help="Do not create .env from .env.example.",
    )

    cert_parser = subparsers.add_parser(
        "createcrt",
        help="Generate a self-signed TLS certificate for local testing.",
    )
    cert_parser.add_argument(
        "--name",
        default="server",
        help="Base filename for the generated certificate and key.",
    )
    cert_parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="Certificate validity period in days.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse CLI arguments and dispatch commands."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "init":
        return run_init(copy_env=not args.no_env)
    if args.command == "createcrt":
        return run_createcrt(name=args.name, days=args.days)

    parser.error(f"Unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
