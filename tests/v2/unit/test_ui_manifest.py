"""The UI build manifest (`ui-manifest.json`): strict validation, and what the app does with it."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from v2.pipeline_support import FakeGemini, gemini_ok
from v2.unit.test_service import llm_factory, make_config
from v2.web_support import BASE, HttpsClient, make_web
from wazuh_ai_analyzer import service as service_module
from wazuh_ai_analyzer.service import Service
from wazuh_ai_analyzer.web.app import LiveState, create_app
from wazuh_ai_analyzer.web.ui_manifest import (
    MANIFEST_NAME,
    UiManifest,
    UiManifestError,
    load_ui_manifest,
)

HASH = "sha256-" + "A" * 43 + "="


def write_ui(root: Path, manifest: object | None = None) -> Path:
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("<!doctype html><title>app</title>", encoding="utf-8")
    (root / "login.html").write_text("<!doctype html><title>login</title>", encoding="utf-8")
    (root / "assets" / "login-ab12.js").write_text("export {}", encoding="utf-8")
    (root / "assets" / "font-ab12.woff2").write_bytes(b"wOF2")
    (root / "assets" / "secret.bin").write_bytes(b"x")
    if manifest is None:
        manifest = {
            "version": 1,
            "script_hashes": [HASH],
            "public_files": ["login.html", "assets/login-ab12.js", "assets/font-ab12.woff2"],
        }
    (root / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    return root


def test_no_manifest_means_no_extra_hashes_and_no_extra_public_files(tmp_path: Path) -> None:
    assert load_ui_manifest(tmp_path) == UiManifest()


def test_a_valid_manifest_is_loaded(tmp_path: Path) -> None:
    manifest = load_ui_manifest(write_ui(tmp_path))
    assert manifest.script_hashes == (HASH,)
    assert manifest.public_files == {"login.html", "assets/login-ab12.js", "assets/font-ab12.woff2"}


@pytest.mark.parametrize(
    "manifest",
    [
        [],
        {"version": 2, "script_hashes": [HASH], "public_files": ["login.html"]},
        {"version": 1, "script_hashes": [], "public_files": ["login.html"]},
        {"version": 1, "script_hashes": ["sha256-short"], "public_files": ["login.html"]},
        {"version": 1, "script_hashes": [HASH, 7], "public_files": ["login.html"]},
        {"version": 1, "script_hashes": [HASH], "public_files": []},
        {"version": 1, "script_hashes": [HASH], "public_files": "login.html"},
        {"version": 1, "script_hashes": [HASH], "public_files": [3]},
        # not a plain relative path
        {"version": 1, "script_hashes": [HASH], "public_files": ["../login.html"]},
        {"version": 1, "script_hashes": [HASH], "public_files": ["assets/../login.html"]},
        {"version": 1, "script_hashes": [HASH], "public_files": ["/login.html"]},
        {"version": 1, "script_hashes": [HASH], "public_files": ["assets\\login-ab12.js"]},
        {"version": 1, "script_hashes": [HASH], "public_files": [".hidden.js"]},
        {"version": 1, "script_hashes": [HASH], "public_files": ["assets/"]},
        # not a file the server would serve
        {"version": 1, "script_hashes": [HASH], "public_files": ["missing.js"]},
        {"version": 1, "script_hashes": [HASH], "public_files": ["assets/secret.bin"]},
        {"version": 1, "script_hashes": [HASH], "public_files": ["assets"]},
    ],
)
def test_an_invalid_manifest_refuses_the_start(tmp_path: Path, manifest: object) -> None:
    root = write_ui(tmp_path, manifest)
    with pytest.raises(UiManifestError):
        load_ui_manifest(root)


def test_a_manifest_that_is_not_json_refuses_the_start(tmp_path: Path) -> None:
    root = write_ui(tmp_path)
    (root / MANIFEST_NAME).write_text("{not json", encoding="utf-8")
    with pytest.raises(UiManifestError):
        load_ui_manifest(root)


def test_a_symlink_out_of_the_root_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside.js"
    outside.write_text("secret", encoding="utf-8")
    root = write_ui(tmp_path / "ui")
    link = root / "assets" / "link.js"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are not available")
    manifest = {"version": 1, "script_hashes": [HASH], "public_files": ["assets/link.js"]}
    (root / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(UiManifestError):
        load_ui_manifest(root)


def test_manifest_files_are_served_without_a_session_and_the_hash_is_in_the_csp(
    tmp_path: Path,
) -> None:
    root = write_ui(tmp_path / "ui")
    manifest = load_ui_manifest(root)
    web = make_web(tmp_path)
    app = create_app(
        web.config,
        web.repo,
        web.sessions,
        LiveState(runtime=dict, buffered_alerts=lambda: 0, quota=dict, upstream=dict),
        session_key=web.key,
        ui_dir=root,
        script_hashes=manifest.script_hashes,
        public_files=manifest.public_files,
    )
    app.test_client_class = HttpsClient
    client = app.test_client()
    for name in manifest.public_files:
        assert client.get("/" + name, base_url=BASE).status_code == 200, name
    # Everything else still needs a session: the app page redirects, other files too.
    assert client.get("/", base_url=BASE).status_code == 302
    assert client.get("/index.html", base_url=BASE).status_code == 302
    assert client.get("/assets/secret.bin", base_url=BASE).status_code == 302
    assert client.get("/api/stats", base_url=BASE).status_code == 401
    csp = client.get("/login", base_url=BASE).headers["Content-Security-Policy"]
    assert f"script-src 'self' '{HASH}'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


def test_the_service_warns_when_the_dashboard_is_not_built(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    empty = tmp_path / "empty-ui"
    empty.mkdir()
    monkeypatch.setattr(service_module, "UI_DIR", empty)
    with caplog.at_level(logging.WARNING):
        service = Service(
            make_config(tmp_path / "data"), backend_factory=llm_factory(FakeGemini(gemini_ok()))
        )
    try:
        assert "The dashboard is not built" in caplog.text
    finally:
        service.shutdown(grace=5)


def test_the_service_refuses_to_start_with_a_broken_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = write_ui(
        tmp_path / "ui", {"version": 1, "script_hashes": [HASH], "public_files": ["x.js"]}
    )
    monkeypatch.setattr(service_module, "UI_DIR", root)
    with pytest.raises(UiManifestError):
        Service(
            make_config(tmp_path / "data"), backend_factory=llm_factory(FakeGemini(gemini_ok()))
        )
