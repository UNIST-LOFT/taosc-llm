"""Request-local authentication boundaries; inert prepared inputs only."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import FrozenInstanceError
import os
import threading

import pytest

from taosc_llm import analysis
from taosc_llm.dataset import load_dataset
from taosc_llm.preparation import prepare_dataset
from test_preparation import mutation_inputs, preparation_inputs


@pytest.fixture
def dataset(tmp_path, monkeypatch):
    monkeypatch.delenv("TAOSC_LLM_REA", raising=False)
    monkeypatch.setattr(analysis.shutil, "which", lambda _: None)
    config, work, concrete = preparation_inputs(tmp_path)
    mutation = mutation_inputs(tmp_path, work)
    return prepare_dataset(config, work, concrete, mutation, output=tmp_path / "dataset")


def owned_path(dataset, kind):
    if kind == "input":
        return dataset.root / dataset.case("system:0")["input_path"]
    if kind == "analysis":
        return dataset.root / dataset.manifest["analysis"][0]["path"]
    if kind == "cases":
        return dataset.root / dataset.manifest["cases"]["path"]
    capture = dataset.case("function:2")["capture"]
    if kind in ("capture", "sidecar"):
        record = capture if kind == "capture" else capture["sidecar"]
        return dataset.root / record["path"]
    return dataset.artifact("config.env" if kind == "env" else "fixture.brcached")


@pytest.mark.parametrize("kind", ["input", "analysis", "cases", "env", "capture", "sidecar", "artifact"])
def test_new_scope_authenticates_same_size_changes_even_with_restored_mtime(dataset, kind):
    path = owned_path(dataset, kind)
    original = path.read_bytes()
    before = path.stat()
    with dataset.validation() as validated:
        assert validated.case("function:2")["capture"]["complete"] is True
    assert original
    path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(ValueError, match="hash mismatch"):
        with dataset.validation():
            pytest.fail("tampered dataset admitted")
    with pytest.raises(ValueError, match="hash mismatch"):
        dataset.verify_artifacts()
    path.write_bytes(original)
    with dataset.validation() as restored:
        assert restored.case("system:0")["domain"] == "system"


@pytest.mark.parametrize("kind", ["input", "analysis", "env", "capture", "sidecar", "artifact"])
def test_scope_rejects_symlink_to_identical_external_bytes(dataset, tmp_path, kind):
    path = owned_path(dataset, kind)
    external = tmp_path / "outside"
    external.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(external)
    with pytest.raises(ValueError, match="immutable root"):
        with dataset.validation():
            pytest.fail("external symlink admitted")


def test_scope_rejects_parent_directory_symlink_escape(dataset, tmp_path):
    record = dataset.manifest["analysis"][0]
    path = dataset.root / record["path"]
    parent = path.parent
    external = tmp_path / "analysis-outside"
    parent.rename(external)
    parent.symlink_to(external, target_is_directory=True)
    with pytest.raises(ValueError, match="immutable root"):
        with dataset.validation():
            pytest.fail("symlinked analysis directory admitted")


def test_scope_rejects_replaced_root_even_with_identical_files(dataset, tmp_path):
    root = dataset.root
    moved = tmp_path / "moved"
    root.rename(moved)
    root.symlink_to(moved, target_is_directory=True)
    with pytest.raises(ValueError, match="root"):
        with dataset.validation():
            pytest.fail("replaced dataset root admitted")


@pytest.mark.parametrize("error_exit", [False, True])
def test_nested_scope_lifetime_and_expiry(dataset, error_exit):
    class Stop(Exception):
        pass

    view = None
    try:
        with dataset.validation() as view:
            with view.validation() as nested:
                assert nested.case("system:0")["domain"] == "system"
            assert view.case("system:0")["domain"] == "system"
            if error_exit:
                raise Stop()
    except Stop:
        pass
    for operation in (lambda: view.cases(), lambda: view.execution_environment(),
                      lambda: view.snapshots({}), lambda: view.artifact("fixture.orig"),
                      lambda: view.dataset_id, lambda: view.root):
        with pytest.raises(ValueError, match="expired"):
            operation()
    with pytest.raises(ValueError, match="expired"):
        with view.validation():
            pytest.fail("expired validation reused")
    with dataset.validation() as fresh:
        assert fresh.case("system:0")["domain"] == "system"


@pytest.mark.parametrize("field,value", [
    ("descriptor", ""), ("descriptor", "c1p16"),
    ("descriptor", "c1p0"),
    ("branches", [1]), ("patch_id", 9), ("complete", False),
    ("artifact_sha256", "0" * 64),
])
def test_cached_capture_still_binds_all_metadata(dataset, field, value):
    with dataset.validation() as view:
        capture = view.case("function:2")["capture"]
        assert len(view.snapshots(capture)) == 1
        changed = {**capture, field: value}
        with pytest.raises(ValueError):
            view.snapshots(changed)
        assert view.snapshots(capture)[0].branch == 0


def test_cached_capture_still_authenticates_sidecar_metadata(dataset):
    with dataset.validation() as view:
        capture = view.case("function:2")["capture"]
        view.snapshots(capture)
        changed = deepcopy(capture)
        changed["sidecar"]["sha256"] = "0" * 64
        with pytest.raises(ValueError, match="hash mismatch"):
            view.snapshots(changed)


def test_shared_view_returns_independent_containers_and_immutable_states(dataset):
    with dataset.validation() as view:
        capture = view.case("function:2")["capture"]
        def read(_):
            rows = view.cases()
            rows[0]["domain"] = "changed"
            env = view.execution_environment()
            env["BINARY"] = "changed"
            states = view.snapshots(capture)
            state = states.pop()
            with pytest.raises(FrozenInstanceError):
                state.branch = 1
            assert view.case("system:0")["domain"] == "system"
            assert view.execution_environment()["BINARY"] == "fixture"
            assert view.snapshots(capture)[0].branch == 0
        with ThreadPoolExecutor(max_workers=4) as workers:
            list(workers.map(read, range(8)))


def test_independent_thread_scopes_do_not_share_lifetime_or_mutable_data(dataset):
    barrier = threading.Barrier(2)
    first_exited = threading.Event()
    def first():
        with dataset.validation() as view:
            rows = view.cases()
            rows[0]["domain"] = "changed"
            barrier.wait()
        first_exited.set()
        with pytest.raises(ValueError, match="expired"):
            view.cases()
    def second():
        with dataset.validation() as view:
            barrier.wait()
            assert first_exited.wait(5)
            assert view.case("system:0")["domain"] == "system"
            assert view.snapshots(view.case("function:2")["capture"])[0].branch == 0
    with ThreadPoolExecutor(max_workers=2) as workers:
        tasks = [workers.submit(first), workers.submit(second)]
        for task in tasks:
            task.result()


def test_load_returns_independently_authenticating_unscoped_dataset(dataset):
    loaded = load_dataset(dataset.root)
    capture = loaded.case("function:2")["capture"]
    with loaded.validation():
        pass
    path = loaded.root / capture["path"]
    path.write_bytes(b"changed")
    with pytest.raises(ValueError, match="hash mismatch"):
        loaded.snapshots(capture)
    with pytest.raises(ValueError, match="hash mismatch"):
        with loaded.validation():
            pytest.fail("loaded dataset retained trust")
