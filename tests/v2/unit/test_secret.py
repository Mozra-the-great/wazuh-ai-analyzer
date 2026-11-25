"""Secret wrapper and secret files (S7)."""

from __future__ import annotations

import copy
import os
import pickle
from pathlib import Path

import pytest

from wazuh_ai_analyzer.secret import (
    SECRET_FILE_MAX_BYTES,
    Secret,
    SecretFileError,
    read_secret_file,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="needs POSIX owners and modes")
VALUE = "AIza-super-secret-value"


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
