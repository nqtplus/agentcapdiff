from __future__ import annotations

import errno
import os
import stat
import tempfile
from contextlib import suppress
from pathlib import Path


class OutputWriteError(ValueError):
    """Raised when an explicit output path cannot be written safely."""


def _absolute_path(path: Path) -> Path:
    try:
        return Path(os.path.abspath(os.fspath(path)))
    except (OSError, TypeError, ValueError) as exc:
        raise OutputWriteError(f"invalid output path: {path}") from exc


def _validate_target_stat(target_stat: os.stat_result, path: Path) -> int:
    if stat.S_ISLNK(target_stat.st_mode):
        raise OutputWriteError(f"refusing symlinked output path: {path}")
    if not stat.S_ISREG(target_stat.st_mode):
        raise OutputWriteError(f"output path must be a regular file: {path}")
    return stat.S_IMODE(target_stat.st_mode) & 0o777


def _parent_open_flags() -> int:
    access = getattr(os, "O_PATH", os.O_RDONLY)
    return (
        access
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_parent_posix(parent: Path) -> int:
    flags = _parent_open_flags()
    current_fd = os.open("/", flags)
    try:
        for component in parent.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
    except BaseException:
        os.close(current_fd)
        raise
    return current_fd


def _target_mode_posix(parent_fd: int, name: str, path: Path) -> int | None:
    try:
        target_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return _validate_target_stat(target_stat, path)


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "short write while creating output")
        offset += written


def _atomic_write_posix(path: Path, payload: bytes) -> None:
    parent_fd = _open_parent_posix(path.parent)
    temp_name: str | None = None
    temp_fd: int | None = None
    try:
        existing_mode = _target_mode_posix(parent_fd, path.name, path)
        create_mode = existing_mode if existing_mode is not None else 0o666

        for _ in range(16):
            candidate = f".{path.name}.agentcapdiff-{os.getpid()}-{os.urandom(8).hex()}.tmp"
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                temp_fd = os.open(candidate, flags, create_mode, dir_fd=parent_fd)
            except FileExistsError:
                continue
            temp_name = candidate
            break
        if temp_fd is None or temp_name is None:
            raise OutputWriteError(f"cannot allocate temporary output file: {path}")

        if existing_mode is not None:
            os.fchmod(temp_fd, existing_mode)
        _write_all(temp_fd, payload)
        os.fsync(temp_fd)

        # Keep the destination contract fail-closed if it became unsafe while we wrote.
        _target_mode_posix(parent_fd, path.name, path)
        os.close(temp_fd)
        temp_fd = None

        # Atomic replacement never follows the destination symlink. Even if another
        # process races after the check above, the directory entry itself is replaced.
        os.replace(
            temp_name,
            path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temp_name = None
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        if temp_name is not None:
            with suppress(FileNotFoundError):
                os.unlink(temp_name, dir_fd=parent_fd)
        os.close(parent_fd)


def _portable_parent(parent: Path) -> Path:
    try:
        resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise OutputWriteError(f"output parent directory is unavailable: {parent}") from exc
    if not resolved.is_dir():
        raise OutputWriteError(f"output parent must be a directory: {parent}")

    current = Path(parent.anchor)
    for component in parent.parts[1:]:
        current /= component
        try:
            current_stat = current.lstat()
        except OSError as exc:
            raise OutputWriteError(f"output parent directory is unavailable: {current}") from exc
        if stat.S_ISLNK(current_stat.st_mode):
            raise OutputWriteError(f"refusing symlinked output parent: {current}")

    if os.path.normcase(str(resolved)) != os.path.normcase(str(parent)):
        raise OutputWriteError(f"refusing redirected output parent: {parent}")
    return resolved


def _target_mode_portable(path: Path) -> int | None:
    try:
        target_stat = path.lstat()
    except FileNotFoundError:
        return None
    return _validate_target_stat(target_stat, path)


def _atomic_write_portable(path: Path, payload: bytes) -> None:
    parent = _portable_parent(path.parent)
    target = parent / path.name
    existing_mode = _target_mode_portable(target)
    temp_fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.agentcapdiff-", dir=parent)
    temp_path = Path(temp_name)
    try:
        if existing_mode is not None:
            os.chmod(temp_path, existing_mode)
        _write_all(temp_fd, payload)
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = -1

        _target_mode_portable(target)
        os.replace(temp_path, target)
    finally:
        if temp_fd >= 0:
            os.close(temp_fd)
        with suppress(FileNotFoundError):
            temp_path.unlink()


def atomic_write_text(path: Path, text: str) -> None:
    """Write UTF-8 text atomically without following output-path symlinks.

    Existing regular files are replaced only after the complete new contents have
    been written and fsynced in the same directory. Parent directories must already
    exist. On POSIX, parent traversal is pinned with no-follow directory descriptors
    so a symlink swap cannot redirect the write to another tree.
    """

    target = _absolute_path(path)
    if not target.name:
        raise OutputWriteError(f"output path must name a file: {path}")
    payload = text.encode("utf-8")

    try:
        if os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"):
            _atomic_write_posix(target, payload)
        else:
            _atomic_write_portable(target, payload)
    except OutputWriteError:
        raise
    except (OSError, ValueError) as exc:
        raise OutputWriteError(f"cannot write output safely: {target}: {exc}") from exc
