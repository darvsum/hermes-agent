"""Shared file safety rules used by both tools and ACP shims."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def _hermes_home_path() -> Path:
    """Resolve the active HERMES_HOME (profile-aware) without circular imports."""
    try:
        from hermes_constants import get_hermes_home  # local import to avoid cycles
        return get_hermes_home()
    except Exception:
        return Path(os.path.expanduser("~/.hermes"))


def build_write_denied_paths(home: str) -> set[str]:
    """Return exact sensitive paths that must never be written."""
    hermes_home = _hermes_home_path()
    return {
        os.path.realpath(p)
        for p in [
            os.path.join(home, ".ssh", "authorized_keys"),
            os.path.join(home, ".ssh", "id_rsa"),
            os.path.join(home, ".ssh", "id_ed25519"),
            os.path.join(home, ".ssh", "config"),
            str(hermes_home / ".env"),
            os.path.join(home, ".bashrc"),
            os.path.join(home, ".zshrc"),
            os.path.join(home, ".profile"),
            os.path.join(home, ".bash_profile"),
            os.path.join(home, ".zprofile"),
            os.path.join(home, ".netrc"),
            os.path.join(home, ".pgpass"),
            os.path.join(home, ".npmrc"),
            os.path.join(home, ".pypirc"),
            "/etc/sudoers",
            "/etc/passwd",
            "/etc/shadow",
        ]
    }


def build_write_denied_prefixes(home: str) -> list[str]:
    """Return sensitive directory prefixes that must never be written."""
    return [
        os.path.realpath(p) + os.sep
        for p in [
            os.path.join(home, ".ssh"),
            os.path.join(home, ".aws"),
            os.path.join(home, ".gnupg"),
            os.path.join(home, ".kube"),
            "/etc/sudoers.d",
            "/etc/systemd",
            os.path.join(home, ".docker"),
            os.path.join(home, ".azure"),
            os.path.join(home, ".config", "gh"),
        ]
    ]


def get_safe_write_root() -> Optional[str]:
    """Return the resolved HERMES_WRITE_SAFE_ROOT path, or None if unset."""
    root = os.getenv("HERMES_WRITE_SAFE_ROOT", "")
    if not root:
        return None
    try:
        return os.path.realpath(os.path.expanduser(root))
    except Exception:
        return None


def _build_sandbox_protected_paths(sandbox_root: str) -> set[str]:
    """Return paths inside the sandbox that must never be written.

    These are configuration and credential files that, if modified by the
    agent, would weaken or bypass the sandbox itself.
    """
    root = Path(sandbox_root)
    protected_names = [
        "config.yaml",
        ".env",
        "approved.json",
        "accounts",      # weixin token directory
    ]
    result = set()
    for name in protected_names:
        p = (root / name).resolve()
        result.add(str(p))
        # Also protect the directory itself for "accounts"
        if name == "accounts":
            result.add(str(p) + os.sep)
    return result


def _build_sandbox_protected_prefixes(sandbox_root: str) -> list[str]:
    """Return directory prefixes inside the sandbox that must never be written."""
    root = Path(sandbox_root)
    return [
        str((root / "accounts").resolve()) + os.sep,
        str((root / "weixin").resolve()) + os.sep,
    ]


def is_write_denied(path: str) -> bool:
    """Return True if path is blocked by the write denylist or safe root
    or falls outside the configured file sandbox."""
    home = os.path.realpath(os.path.expanduser("~"))
    resolved = os.path.realpath(os.path.expanduser(str(path)))

    if resolved in build_write_denied_paths(home):
        return True
    for prefix in build_write_denied_prefixes(home):
        if resolved.startswith(prefix):
            return True

    safe_root = get_safe_write_root()
    if safe_root and not (resolved == safe_root or resolved.startswith(safe_root + os.sep)):
        return True

    # ── File sandbox restriction (read boundary) ──────────────────────
    # When HERMES_FILE_SANDBOX is set, writes must also fall inside it.
    sandbox = os.getenv("HERMES_FILE_SANDBOX", "")
    if sandbox:
        sandbox_root = os.path.realpath(os.path.expanduser(sandbox))
        if not (resolved == sandbox_root or resolved.startswith(sandbox_root + os.sep)):
            return True
        # Even inside the sandbox, protect config/credential files that
        # could be used to weaken or bypass the sandbox itself.
        for pp in _build_sandbox_protected_paths(sandbox_root):
            if resolved == pp or (pp.endswith(os.sep) and resolved.startswith(pp)):
                return True
        for prefix in _build_sandbox_protected_prefixes(sandbox_root):
            if resolved.startswith(prefix):
                return True

    # ── Write sandbox restriction (write boundary) ────────────────────
    # When HERMES_FILE_WRITE_SANDBOX is set, writes are restricted to
    # this narrower directory (typically the workspace/ subdirectory).
    # This is stricter than HERMES_FILE_SANDBOX which controls reads.
    write_sandbox = os.getenv("HERMES_FILE_WRITE_SANDBOX", "")
    if write_sandbox:
        write_root = os.path.realpath(os.path.expanduser(write_sandbox))
        if not (resolved == write_root or resolved.startswith(write_root + os.sep)):
            return True

    return False


def get_read_block_error(path: str) -> Optional[str]:
    """Return an error message when a read targets internal Hermes cache files
    or falls outside the configured file sandbox."""
    resolved = Path(path).expanduser().resolve()
    hermes_home = _hermes_home_path().resolve()

    # ── File sandbox restriction ──────────────────────────────────────
    # When HERMES_FILE_SANDBOX is set, only paths under that root are
    # readable.  This prevents users from reading other profiles' config
    # files, API keys, or any system files outside their workspace.
    sandbox = os.getenv("HERMES_FILE_SANDBOX", "")
    if sandbox:
        sandbox_root = Path(sandbox).expanduser().resolve()
        try:
            resolved.relative_to(sandbox_root)
        except ValueError:
            return (
                f"Access denied: {path} is outside the allowed workspace. "
                f"File access is restricted to {sandbox_root} and its subdirectories."
            )
        # Even inside the sandbox, block reading sensitive config/credential
        # files that contain API keys or could weaken the sandbox.
        _sandbox_root_str = str(sandbox_root)
        for pp in _build_sandbox_protected_paths(_sandbox_root_str):
            pp_path = Path(pp)
            if resolved == pp_path or resolved.is_relative_to(pp_path):
                return (
                    f"Access denied: {path} contains sensitive configuration "
                    f"and cannot be read for security reasons."
                )
        for prefix in _build_sandbox_protected_prefixes(_sandbox_root_str):
            prefix_path = Path(prefix.rstrip(os.sep))
            if resolved.is_relative_to(prefix_path):
                return (
                    f"Access denied: {path} contains sensitive credentials "
                    f"and cannot be read for security reasons."
                )

    # ── Hermes internal cache guard ───────────────────────────────────
    blocked_dirs = [
        hermes_home / "skills" / ".hub" / "index-cache",
        hermes_home / "skills" / ".hub",
    ]
    for blocked in blocked_dirs:
        try:
            resolved.relative_to(blocked)
        except ValueError:
            continue
        return (
            f"Access denied: {path} is an internal Hermes cache file "
            "and cannot be read directly to prevent prompt injection. "
            "Use the skills_list or skill_view tools instead."
        )
    return None
