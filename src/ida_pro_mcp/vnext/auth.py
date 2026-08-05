"""Bearer-token and canonical workspace-path policy."""

from __future__ import annotations

import hmac
import ipaddress
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .contracts import ErrorCode, VNextError


def create_token() -> str:
    """Return a 256-bit URL-safe bearer token."""

    return secrets.token_urlsafe(32)


def default_token_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        root = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return root / "ida-pro-mcp" / "auth-token"


def load_token_file(path: Path) -> str:
    token = path.read_text(encoding="utf-8").strip()
    if not token:
        raise VNextError(ErrorCode.AUTH_REQUIRED, f"Bearer token file is empty: {path}")
    return token


def is_loopback_bind(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(slots=True)
class AuthPolicy:
    bound_host: str
    bearer_token: str | None = None

    @property
    def token_required(self) -> bool:
        return not is_loopback_bind(self.bound_host)

    def validate_configuration(self) -> None:
        if self.token_required and not self.bearer_token:
            raise VNextError(
                ErrorCode.AUTH_REQUIRED,
                "A bearer token is required for non-loopback HTTP bindings",
            )

    def authorize_header(self, authorization: str | None) -> None:
        if not self.token_required and not self.bearer_token:
            return
        expected = self.bearer_token or ""
        scheme, separator, supplied = (authorization or "").partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not supplied:
            raise VNextError(ErrorCode.AUTH_REQUIRED, "Missing bearer authorization")
        if not hmac.compare_digest(supplied, expected):
            raise VNextError(ErrorCode.AUTH_REQUIRED, "Invalid bearer authorization")


@dataclass(slots=True)
class WorkspacePolicy:
    roots: tuple[Path, ...] = field(default_factory=tuple)

    @classmethod
    def from_values(cls, roots: Iterable[str | os.PathLike[str]]) -> "WorkspacePolicy":
        return cls(tuple(Path(root).expanduser().resolve(strict=False) for root in roots))

    def resolve(self, value: str | os.PathLike[str], *, must_exist: bool = False) -> Path:
        candidate = Path(value).expanduser().resolve(strict=must_exist)
        if not self.roots:
            return candidate
        if any(_is_relative_to(candidate, root) for root in self.roots):
            return candidate
        raise VNextError(
            ErrorCode.PROFILE_DENIED,
            "Path is outside configured workspace roots",
            details={"path": str(candidate), "roots": [str(root) for root in self.roots]},
        )


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def write_token_file(path: Path, token: str) -> None:
    """Create or replace a token file with restrictive POSIX permissions.

    Windows ACL inheritance remains in effect; the file is still created only
    for the current user by default in the user's application-data directory.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, (token + "\n").encode("utf-8"))
    finally:
        os.close(descriptor)
