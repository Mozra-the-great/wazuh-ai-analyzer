"""#39: requirements.txt must be fully hash-pinned (installed with --require-hashes)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _requirements(name):
    text = (ROOT / name).read_text(encoding="utf-8").replace("\\\n", " ")
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def test_every_requirement_is_pinned_and_hashed():
    lines = _requirements("requirements.txt")
    assert lines, "requirements.txt is empty"
    for ln in lines:
        assert re.match(r"^[A-Za-z0-9_.-]+==[0-9][^\s;]*", ln), f"not an exact pin: {ln}"
        assert re.search(r"--hash=sha256:[0-9a-f]{64}", ln), f"no sha256 hash: {ln}"


def test_direct_dependencies_are_locked_at_the_same_version():
    locked = {m.group(1).lower(): m.group(2)
              for ln in _requirements("requirements.txt")
              if (m := re.match(r"^([A-Za-z0-9_.-]+)==([^\s;]+)", ln))}
    for ln in _requirements("requirements.in"):
        name, version = ln.split("==")
        assert locked.get(name.lower()) == version, f"{name} differs between .in and .txt"
