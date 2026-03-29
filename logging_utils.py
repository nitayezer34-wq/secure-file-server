"""Shared structured logging helpers."""

import logging
from typing import Optional


def log_event(
    level: int,
    component: str,
    event: str,
    action: str,
    status: str,
    client_ip: str,
    request_id: Optional[str] = None,
    **fields,
) -> None:
    """Log one structured event using a consistent key=value format."""
    parts = [
        f"component={component}",
        f"event={event}",
        f"action={action}",
        f"status={status}",
        f"client_ip={client_ip}",
        f"request_id={request_id or '-'}",
    ]
    for key, value in fields.items():
        if value is None or value == "":
            continue
        parts.append(f"{key}={value}")
    logging.log(level, " ".join(parts))
