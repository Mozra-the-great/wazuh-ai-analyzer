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


def read_secret_file(path: str, *, systemd_credential: bool = False) -> str:
    """Read a secret from a file the service user owns exclusively (0600 / 0400).

    Refuses (raises `SecretFileError`) a missing file, a symlink, anything that is
    not a regular file, a file owned by someone else, a file that group or others
    can access, and an oversized file. The checks run on the opened descriptor,
    so the file cannot be swapped between the check and the read. On platforms
    without POSIX owners and modes only the type and size checks apply. Messages
    never contain file contents.

    `systemd_credential=True` is for a file inside `$CREDENTIALS_DIRECTORY`
    (`LoadCredential=`). systemd normally chowns such a file to the service user
    with mode 0400. Where it cannot (no tmpfs/ramfs for the credentials directory,
    for example in a container), it leaves the file owned by root and grants the
    service user read access through a POSIX ACL, and the group bits of the mode
    then show the ACL mask (0440). The directory itself is private to the service
    user, so for these files the owner may also be root and the group bits are not
    judged; access for others is still refused.
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
            _check_owner_and_mode(path, info, systemd_credential)
        if info.st_size > SECRET_FILE_MAX_BYTES:
            raise SecretFileError(f"{path}: larger than {SECRET_FILE_MAX_BYTES} bytes")
        data = os.read(fd, SECRET_FILE_MAX_BYTES + 1)
    finally:
        os.close(fd)
    try:
        return data.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise SecretFileError(f"{path}: not valid UTF-8 text") from None


def _check_owner_and_mode(path: str, info: os.stat_result, systemd_credential: bool) -> None:
    owners = {os.geteuid()}
    forbidden = 0o077
    if systemd_credential:
        owners.add(0)
        forbidden = 0o007
    if info.st_uid not in owners:
        raise SecretFileError(f"{path}: must be owned by the service user")
    if info.st_mode & forbidden:
        advice = "others must have no access" if systemd_credential else "use 0600 or 0400"
        raise SecretFileError(
            f"{path}: mode {stat.S_IMODE(info.st_mode):04o} is too permissive, {advice}"
        )
