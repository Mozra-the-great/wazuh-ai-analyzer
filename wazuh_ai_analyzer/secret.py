"""Secret values that cannot leak through `repr`, `str`, f-strings or pickling (S7)."""

from __future__ import annotations

import hmac
import os
import stat
from typing import Any, NoReturn

# A key file is a few dozen bytes; anything bigger is not a key file.
SECRET_FILE_MAX_BYTES = 4096


class Secret:
    """Wraps a secret string. The only way to the value is `reveal()`.

    `repr()`, `str()` and format specs all give `***`, so a config object or a
    log call that includes a secret never shows it. The wrapper is immutable,
    cannot be pickled and compares in constant time.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        object.__setattr__(self, "_value", value)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError("Secret is immutable")

    def reveal(self) -> str:
        """The wrapped value. Call this only where it is actually used."""
        value: str = object.__getattribute__(self, "_value")
        return value

    def __repr__(self) -> str:
        return "***"

    def __str__(self) -> str:
        return "***"

    def __bool__(self) -> bool:
        return bool(self.reveal())

    def __len__(self) -> int:
        return len(self.reveal())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self.reveal().encode(), other.reveal().encode())

    def __hash__(self) -> int:
        return hash(self.reveal())

    def __copy__(self) -> Secret:
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> Secret:
        return self

    def __reduce__(self) -> NoReturn:
        raise TypeError("Secret cannot be pickled")


class SecretFileError(Exception):
    """A secret file is missing, unreadable, too permissive or has a wrong owner."""


def read_secret_file(path: str) -> str:
    """Read a secret from a file the service user owns exclusively (0600 / 0400).

    Refuses (raises `SecretFileError`) a missing file, a symlink, anything that is
    not a regular file, a file owned by someone else, a file that group or others
    can access, and an oversized file. The checks run on the opened descriptor,
    so the file cannot be swapped between the check and the read. On platforms
    without POSIX owners and modes only the type and size checks apply. Messages
    never contain file contents.
    """
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise SecretFileError(f"{path}: file does not exist") from None
    except PermissionError:
        raise SecretFileError(f"{path}: not readable by the service user") from None
    except OSError as exc:
        # ELOOP is what O_NOFOLLOW reports for a symlink.
        raise SecretFileError(f"{path}: cannot be opened ({exc.strerror or 'error'})") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SecretFileError(f"{path}: not a regular file")
        if hasattr(os, "geteuid"):
            if info.st_uid != os.geteuid():
                raise SecretFileError(f"{path}: must be owned by the service user")
            if info.st_mode & 0o077:
                raise SecretFileError(
                    f"{path}: mode {stat.S_IMODE(info.st_mode):04o} is too permissive,"
                    " use 0600 or 0400"
                )
        if info.st_size > SECRET_FILE_MAX_BYTES:
            raise SecretFileError(f"{path}: larger than {SECRET_FILE_MAX_BYTES} bytes")
        data = os.read(fd, SECRET_FILE_MAX_BYTES + 1)
    finally:
        os.close(fd)
    try:
        return data.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise SecretFileError(f"{path}: not valid UTF-8 text") from None
