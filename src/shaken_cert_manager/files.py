"""Filesystem helpers for SHAKEN certificate management."""

from __future__ import annotations

import fcntl
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any

from shaken_cert_manager.errors import LockError

LOGGER = logging.getLogger(__name__)


class FileLock:
    """Exclusive file lock for mutating manager commands."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.file_descriptor: int | None = None

    def __enter__(self) -> FileLock:
        """Acquire the lock.

        :return: This lock.
        :rtype: FileLock
        """

        self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        LOGGER.debug("Acquiring manager lock: path=%s", self.path)
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            message = self.lock_held_message()
            LOGGER.debug("Manager lock is already held: path=%s", self.path)
            os.close(descriptor)
            raise LockError(message) from exc
        self.file_descriptor = descriptor
        os.ftruncate(descriptor, 0)
        os.write(
            descriptor, f"pid={os.getpid()} started_at={now_utc()}\n".encode("utf-8")
        )
        LOGGER.debug("Manager lock acquired: path=%s", self.path)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Release the lock.

        :param exc_type: Exception type.
        :type exc_type: type[BaseException] | None
        :param exc_value: Exception value.
        :type exc_value: BaseException | None
        :param traceback: Traceback.
        :type traceback: TracebackType | None
        :return: None.
        :rtype: None
        """

        if self.file_descriptor is not None:
            LOGGER.debug("Releasing manager lock: path=%s", self.path)
            fcntl.flock(self.file_descriptor, fcntl.LOCK_UN)
            os.close(self.file_descriptor)
            self.file_descriptor = None

    def lock_held_message(self) -> str:
        """Return an informative lock contention message.

        :return: Lock contention message.
        :rtype: str
        """

        details = read_lock_file(self.path)
        message = f"Another shaken-cert-manager process holds {self.path}"
        if details:
            message = f"{message}: {details}"
        return (
            f"{message}. If no manager process is running, clear the stale lock "
            "with: shaken-cert-manager --config <config.yaml> clear-lock"
        )


def read_lock_file(path: Path) -> str:
    """Read lock metadata if it exists.

    :param path: Lock path.
    :type path: Path
    :return: Lock metadata.
    :rtype: str
    """

    try:
        return path.read_text().strip()
    except OSError:
        return ""


def clear_stale_lock(path: Path) -> str:
    """Clear a lock file only when no process currently holds it.

    :param path: Lock path.
    :type path: Path
    :return: Cleared lock metadata.
    :rtype: str
    :raises LockError: If the lock is currently held.
    """

    if not path.exists():
        LOGGER.debug("No stale lock file to clear: path=%s", path)
        return ""
    details = read_lock_file(path)
    try:
        descriptor = os.open(path, os.O_RDWR)
    except FileNotFoundError:
        return ""
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            message = f"Cannot clear {path}; another manager process still holds it"
            if details:
                message = f"{message}: {details}"
            LOGGER.debug(
                "Refusing to clear held lock: path=%s details=%s", path, details
            )
            raise LockError(message) from exc
        path.unlink(missing_ok=True)
        LOGGER.info("Cleared stale manager lock: path=%s", path)
        return details
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def now_utc() -> str:
    """Return a UTC timestamp.

    :return: Timestamp.
    :rtype: str
    """

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def atomic_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    """Write text atomically.

    :param path: Destination path.
    :type path: Path
    :param content: Text content.
    :type content: str
    :param mode: File mode.
    :type mode: int
    :return: None.
    :rtype: None
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    temporary_path.write_text(content)
    os.chmod(temporary_path, mode)
    os.replace(temporary_path, path)


def atomic_write_bytes(path: Path, content: bytes, mode: int = 0o600) -> None:
    """Write bytes atomically.

    :param path: Destination path.
    :type path: Path
    :param content: Bytes content.
    :type content: bytes
    :param mode: File mode.
    :type mode: int
    :return: None.
    :rtype: None
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    temporary_path.write_bytes(content)
    os.chmod(temporary_path, mode)
    os.replace(temporary_path, path)


def atomic_write_json(path: Path, content: dict[str, Any], mode: int = 0o600) -> None:
    """Write JSON atomically.

    :param path: Destination path.
    :type path: Path
    :param content: JSON content.
    :type content: dict[str, Any]
    :param mode: File mode.
    :type mode: int
    :return: None.
    :rtype: None
    """

    atomic_write_text(path, json.dumps(content, indent=2, sort_keys=True) + "\n", mode)


def read_json(path: Path) -> dict[str, Any]:
    """Read a JSON object from disk.

    :param path: JSON path.
    :type path: Path
    :return: JSON object.
    :rtype: dict[str, Any]
    """

    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"JSON path is not an object: {path}")
    return value
