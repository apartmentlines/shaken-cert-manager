"""Exceptions raised by the SHAKEN certificate manager."""

from __future__ import annotations


class ManagerError(RuntimeError):
    """Raised when SHAKEN certificate management fails."""


class ConfigError(ManagerError):
    """Raised when manager configuration is invalid."""


class ValidationError(ManagerError):
    """Raised when a certificate or runtime state validation fails."""


class LockError(ManagerError):
    """Raised when the manager lock cannot be acquired."""
