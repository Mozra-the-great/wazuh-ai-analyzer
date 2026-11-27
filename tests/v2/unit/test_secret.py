"""Secret wrapper and secret files (S7)."""

from __future__ import annotations

import copy
import os
import pickle
import stat
from pathlib import Path

import pytest

from wazuh_ai_analyzer.secret import (
    SECRET_FILE_MAX_BYTES,
    Secret,
    SecretFileError,
    read_secret_file,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="needs POSIX owners and modes")
VALUE = "dummy-wrapper-secret-0005"


def test_secret_never_shows_its_value() -> None:
    secret = Secret(VALUE)
    assert repr(secret) == "***"
    assert str(secret) == "***"
    assert f"{secret}" == "***"
    assert f"{secret!r}" == "***"
    assert "%s" % secret == "***"  # noqa: UP031
    assert VALUE not in repr({"key": secret, "list": [secret]})
    assert secret.reveal() == VALUE


def test_secret_is_immutable_and_cannot_be_pickled() -> None:
    secret = Secret(VALUE)
    with pytest.raises(AttributeError):
        secret._value = "other"
    with pytest.raises(TypeError):
        pickle.dumps(secret)
    assert copy.copy(secret) is secret
    assert copy.deepcopy(secret) is secret


def test_secret_equality_and_truthiness() -> None:
    assert Secret("a") == Secret("a")
    assert Secret("a") != Secret("b")
    assert Secret("a") != "a"
    assert hash(Secret("a")) == hash(Secret("a"))
    assert bool(Secret("x"))
    assert not Secret("")
    assert len(Secret("abc")) == 3


def _write(path: Path, content: bytes | str, mode: int) -> Path:
    if isinstance(content, str):
        content = content.encode()
    path.write_bytes(content)
    path.chmod(mode)
    return path


@posix_only
@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_reads_a_private_key_file_and_strips_the_newline(tmp_path: Path, mode: int) -> None:
    key = _write(tmp_path / "key", VALUE + "\n", mode)
    assert read_secret_file(str(key)) == VALUE


@posix_only
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o666])
def test_refuses_a_file_others_can_access(tmp_path: Path, mode: int) -> None:
    key = _write(tmp_path / "key", VALUE, mode)
    with pytest.raises(SecretFileError, match="too permissive") as info:
        read_secret_file(str(key))
    assert VALUE not in str(info.value)


@posix_only
def test_refuses_a_file_of_another_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key = _write(tmp_path / "key", VALUE, 0o600)
    monkeypatch.setattr(os, "geteuid", lambda: key.stat().st_uid + 1)
    with pytest.raises(SecretFileError, match="owned by the service user"):
        read_secret_file(str(key))


@posix_only
def test_refuses_a_symlink(tmp_path: Path) -> None:
    target = _write(tmp_path / "real", VALUE, 0o600)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(SecretFileError):
        read_secret_file(str(link))


def test_refuses_a_missing_file_and_a_directory(tmp_path: Path) -> None:
    with pytest.raises(SecretFileError, match="does not exist"):
        read_secret_file(str(tmp_path / "missing"))
    with pytest.raises(SecretFileError):
        read_secret_file(str(tmp_path))


@posix_only
def test_refuses_oversized_and_non_text_files(tmp_path: Path) -> None:
    big = _write(tmp_path / "big", b"a" * (SECRET_FILE_MAX_BYTES + 1), 0o600)
    with pytest.raises(SecretFileError, match="larger than"):
        read_secret_file(str(big))
    binary = _write(tmp_path / "bin", b"\xff\xfe\x00", 0o600)
    with pytest.raises(SecretFileError, match="UTF-8"):
        read_secret_file(str(binary))


def _as_seen_by_systemd(monkeypatch: pytest.MonkeyPatch, uid: int, mode: int) -> None:
    """Make `os.fstat` report a file owned by `uid` with `mode` (a root-owned ACL file)."""
    real_fstat = os.fstat

    def fake(fd: int) -> os.stat_result:
        info = real_fstat(fd)
        fields = list(info)
        if not stat.S_ISREG(info.st_mode):
            fields[stat.ST_UID] = 0  # the credentials directory: private, owned by root
            return os.stat_result(fields)
        fields[stat.ST_UID] = uid
        fields[stat.ST_MODE] = stat.S_IFREG | mode
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", fake)


@posix_only
def test_a_systemd_credential_may_be_root_owned_with_the_acl_mask_in_the_group_bits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # LoadCredential= without a chown-able credentials directory: owner root, the service
    # user gets read access through an ACL and the group bits show the mask (0440).
    key = _write(tmp_path / "gemini", VALUE + "\n", 0o600)
    monkeypatch.setattr(os, "geteuid", lambda: 4242)
    _as_seen_by_systemd(monkeypatch, uid=0, mode=0o440)
    assert read_secret_file(str(key), systemd_credential=True) == VALUE


@posix_only
@pytest.mark.parametrize(("uid", "mode"), [(4242, 0o400), (4242, 0o440), (0, 0o400)])
def test_a_systemd_credential_owned_by_the_service_user_or_root_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, uid: int, mode: int
) -> None:
    key = _write(tmp_path / "gemini", VALUE, 0o600)
    monkeypatch.setattr(os, "geteuid", lambda: 4242)
    _as_seen_by_systemd(monkeypatch, uid=uid, mode=mode)
    assert read_secret_file(str(key), systemd_credential=True) == VALUE


@posix_only
def test_a_systemd_credential_must_not_be_accessible_to_others(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _write(tmp_path / "gemini", VALUE, 0o600)
    monkeypatch.setattr(os, "geteuid", lambda: 4242)
    _as_seen_by_systemd(monkeypatch, uid=0, mode=0o444)
    with pytest.raises(SecretFileError, match="others must have no access") as info:
        read_secret_file(str(key), systemd_credential=True)
    assert VALUE not in str(info.value)


@posix_only
def test_a_systemd_credential_of_a_third_user_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _write(tmp_path / "gemini", VALUE, 0o600)
    monkeypatch.setattr(os, "geteuid", lambda: 4242)
    _as_seen_by_systemd(monkeypatch, uid=1000, mode=0o400)
    with pytest.raises(SecretFileError, match="owned by the service user"):
        read_secret_file(str(key), systemd_credential=True)


@posix_only
def test_the_credentials_directory_must_not_be_open_to_others(tmp_path: Path) -> None:
    creds = tmp_path / "creds"
    creds.mkdir()
    key = _write(creds / "gemini", VALUE, 0o600)
    creds.chmod(0o755)
    with pytest.raises(SecretFileError, match="credentials directory mode 0755") as info:
        read_secret_file(str(key), systemd_credential=True)
    assert VALUE not in str(info.value)
    creds.chmod(0o750)  # group access is the service group's business, not "others"
    assert read_secret_file(str(key), systemd_credential=True) == VALUE


@posix_only
def test_the_credentials_directory_of_a_third_user_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _write(tmp_path / "gemini", VALUE, 0o600)
    monkeypatch.setattr(os, "geteuid", lambda: tmp_path.stat().st_uid + 1)
    with pytest.raises(SecretFileError, match="credentials directory must be owned"):
        read_secret_file(str(key), systemd_credential=True)


@posix_only
def test_the_credentials_directory_may_be_owned_by_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _write(tmp_path / "gemini", VALUE, 0o600)
    real_fstat = os.fstat

    def as_root(fd: int) -> os.stat_result:
        info = real_fstat(fd)
        if stat.S_ISDIR(info.st_mode):
            fields = list(info)
            fields[stat.ST_UID] = 0
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(os, "fstat", as_root)
    monkeypatch.setattr(os, "geteuid", lambda: tmp_path.stat().st_uid + 1)
    # The file is the current user's, not root's or the faked euid: still refused,
    # but by the file rule, which proves the directory check passed.
    with pytest.raises(SecretFileError, match="owned by the service user"):
        read_secret_file(str(key), systemd_credential=True)


@posix_only
def test_a_symlinked_credentials_directory_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    _write(real / "gemini", VALUE, 0o600)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(SecretFileError, match="credentials directory cannot be opened"):
        read_secret_file(str(link / "gemini"), systemd_credential=True)


@posix_only
@pytest.mark.parametrize(("uid", "mode"), [(0, 0o400), (4242, 0o440)])
def test_a_plain_key_file_keeps_the_strict_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, uid: int, mode: int
) -> None:
    # The relaxation is for the credentials directory only, never for GEMINI_API_KEY_FILE.
    key = _write(tmp_path / "key", VALUE, 0o600)
    monkeypatch.setattr(os, "geteuid", lambda: 4242)
    _as_seen_by_systemd(monkeypatch, uid=uid, mode=mode)
    with pytest.raises(SecretFileError):
        read_secret_file(str(key))
