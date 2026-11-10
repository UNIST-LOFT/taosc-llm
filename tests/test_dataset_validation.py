"""Request-local authentication boundaries; inert prepared inputs only."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import os
import threading

import pytest

from taosc_llm import analysis
from taosc_llm.dataset import canonical, load_dataset, sha256
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


@pytest.mark.parametrize("kind", ["input", "analysis", "capture", "artifact"])
def test_scope_preserves_internal_parent_links_and_rechecks_them_next_operation(dataset, tmp_path, kind):
    path = owned_path(dataset, kind)
    parent = path.parent
    inside = dataset.root / ("relocated-" + parent.name)
    parent.rename(inside)
    parent.symlink_to(inside.name, target_is_directory=True)
    with dataset.validation() as view:
        assert view.case("system:0")["domain"] == "system"
        assert view.snapshots(view.case("function:2")["capture"])[0].branch == 0
        assert view.execution_environment()["BINARY"] == "fixture"
    # Identical bytes cannot authenticate an escaped directory in a new scope,
    # even after its internal alias and shared sibling ancestry were trusted.
    outside = tmp_path / ("outside-" + parent.name)
    inside.rename(outside)
    parent.unlink()
    parent.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="immutable root"):
        with dataset.validation():
            pytest.fail("previous operation's ancestry was trusted")


@pytest.mark.parametrize("replacement", ["directory", "ancestor", "internal-link", "canonical-target", "root"])
def test_unseen_capture_rechecks_current_ancestry_in_same_operation(dataset, tmp_path, replacement):
    parent = dataset.root / "fresh-captures"
    target = dataset.root / "fresh-target"
    if replacement in ("internal-link", "canonical-target"):
        target.mkdir()
        parent.symlink_to(target.name, target_is_directory=True)
    else:
        parent.mkdir()
    nested = parent / "nested"
    nested.mkdir()
    with dataset.validation() as view:
        original = view.case("function:2")["capture"]
        raw = view.capture_bytes(original)
        first_path = nested / "first.brch"
        next_path = nested / "next.brch"
        first_path.write_bytes(raw)
        next_path.write_bytes(raw)
        first = {**original, "path": str(first_path.relative_to(dataset.root))}
        unseen = {**original, "path": str(next_path.relative_to(dataset.root))}
        assert view.snapshots(first)
        outside = tmp_path / "escaped-captures"
        if replacement == "internal-link":
            target.rename(outside)
            parent.unlink()
            parent.symlink_to(outside, target_is_directory=True)
        else:
            moved = {"directory": nested, "ancestor": parent,
                     "canonical-target": target, "root": dataset.root}[replacement]
            moved.rename(outside)
            moved.symlink_to(outside, target_is_directory=True)
        # Matching BRCH bytes and an authenticated sibling must never waive
        # confinement for a path that this operation has not read before.
        with pytest.raises(ValueError, match="immutable root"):
            view.snapshots(unseen)


def test_scope_preserves_ancestor_links_that_return_inside_root(dataset, tmp_path):
    inside = dataset.root / "returned"
    inside.mkdir()
    payload = inside / "payload"
    payload.write_bytes(b"owned artifact")
    outside = tmp_path / "outside-hop"
    outside.mkdir()
    (outside / "back").symlink_to(inside, target_is_directory=True)
    (dataset.root / "hop").symlink_to(outside, target_is_directory=True)
    manifest = deepcopy(dataset.manifest)
    manifest["artifacts"]["returned"] = {"path": "hop/back/payload", "sha256": sha256(payload)}
    manifest.pop("dataset_id")
    manifest["dataset_id"] = hashlib.sha256(canonical(manifest)).hexdigest()
    revision = replace(dataset, manifest=manifest)
    # Existing bound_path semantics inspect the final resolved containment, not
    # an unnecessarily stronger ban on every intermediate symlink target.
    assert revision.artifact("returned").read_bytes() == b"owned artifact"
    with revision.validation() as view:
        assert view.artifact("returned").read_bytes() == b"owned artifact"


@pytest.mark.parametrize("kind", ["input", "analysis", "cases", "env", "capture", "sidecar", "artifact"])
def test_scope_rejects_leaf_symlinks_even_to_identical_internal_bytes(dataset, kind):
    path = owned_path(dataset, kind)
    inside = path.with_name(path.name + ".original")
    path.rename(inside)
    path.symlink_to(inside.name)
    with pytest.raises(ValueError, match="immutable root"):
        with dataset.validation():
            pytest.fail("internal leaf symlink admitted")


def test_scope_rejects_replaced_root_even_with_identical_files(dataset, tmp_path):
    root = dataset.root
    moved = tmp_path / "moved"
    root.rename(moved)
    root.symlink_to(moved, target_is_directory=True)
    with pytest.raises(ValueError, match="root"):
        with dataset.validation():
            pytest.fail("replaced dataset root admitted")


@pytest.mark.parametrize("failure", [FileNotFoundError, PermissionError])
def test_scope_requires_accessible_proc_descriptor_paths(dataset, monkeypatch, failure):
    original = os.readlink

    def unavailable(path, *args, **kwargs):
        if str(path).startswith("/proc/self/fd/"):
            raise failure("proc descriptor paths unavailable")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", unavailable)
    with pytest.raises(ValueError, match="requires accessible Linux /proc/self/fd"):
        with dataset.validation():
            pytest.fail("validation continued without kernel path authentication")


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
    ("branches", [1]), ("branches", [False]), ("branches", None),
    ("patch_id", 9), ("patch_id", False), ("complete", False),
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


def test_public_case_copies_do_not_mutate_authenticated_inventory(dataset):
    with dataset.validation() as view:
        expected = view.case("function:2")
        rows = view.cases("function")
        row = next(item for item in rows if item["id"] == "function:2")
        row["capture"]["branches"].clear()
        row["capture"]["sidecar"]["sha256"] = "0" * 64
        row["source"]["iteration"] = -1
        rows.clear()
        assert view.case("function:2") == expected
        copied = view.case("function:2")
        copied["capture"]["branches"].append(2)
        copied["source"].clear()
        assert next(item for item in view.cases("function") if item["id"] == "function:2") == expected
        assert view.snapshots(expected["capture"])[0].branch == 0


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


def test_operation_capture_bytes_and_vectors_do_not_expose_cached_mutability(dataset, tmp_path):
    from taosc_llm import evaluation
    from taosc_llm.family import parse_candidate
    with dataset.validation() as view:
        relative = view.case('function:2')['capture']
        raw = view.capture_bytes(relative)
        absolute_path = tmp_path / 'owned.brch'
        absolute_path.write_bytes(raw)
        absolute = {**relative, 'path': str(absolute_path)}
        states = evaluation._snapshots(view, absolute)
        assert isinstance(states, tuple)
        assert view.capture_bytes(absolute) == raw
        descriptor = parse_candidate(view.patch_format, '1').descriptor
        branches = evaluation._vector(descriptor, states, dataset=view)
        assert branches == [1] * len(states)
        branches.clear()
        assert evaluation._vector(descriptor, states, dataset=view) == [1] * len(states)
        assert evaluation._vector('p0', states, dataset=view) == [0] * len(states)
        changed = {**absolute, 'patch_id': 99}
        with pytest.raises(ValueError, match='id-mismatch'):
            evaluation._snapshots(view, changed)
        assert evaluation._snapshots(view, absolute) == states
        alternate_path = tmp_path / 'corrupt-alias.brch'
        alternate_path.write_bytes(b'not the authenticated shared bytes')
        with pytest.raises(ValueError, match='capture-hash-mismatch'):
            evaluation._snapshots(view, {**absolute, 'path': str(alternate_path)})
    absolute_path.write_bytes(b'changed after operation')
    with dataset.validation() as view:
        with pytest.raises(ValueError, match='capture-hash-mismatch'):
            evaluation._snapshots(view, absolute)


def test_operation_absolute_sidecar_binding_revalidated_next_scope(dataset, tmp_path):
    import hashlib
    from taosc_llm import evaluation
    with dataset.validation() as view:
        original = view.case('function:2')['capture']
        absolute_path = tmp_path / 'owned.brch'
        absolute_path.write_bytes(view.capture_bytes(original))
        sidecar_path = tmp_path / 'owned.sbsv'
        sidecar_path.write_bytes(b'authenticated sidecar')
        sidecar = {'path': str(sidecar_path), 'sha256': hashlib.sha256(sidecar_path.read_bytes()).hexdigest()}
        capture = {**original, 'path': str(absolute_path), 'sidecar': sidecar}
        assert evaluation._snapshots(view, capture)
        with pytest.raises(ValueError, match='capture-hash-mismatch'):
            evaluation._snapshots(view, {**capture, 'sidecar': {**sidecar, 'sha256': '0' * 64}})
    sidecar_path.write_bytes(b'changed sidecar')
    with dataset.validation() as view:
        with pytest.raises(ValueError, match='capture-hash-mismatch'):
            evaluation._snapshots(view, capture)


def test_vector_cache_never_reuses_mutated_caller_state_lists(dataset):
    from taosc_llm import evaluation
    from taosc_llm.family import parse_candidate
    with dataset.validation() as view:
        states = view.snapshots(view.case('function:2')['capture'])
        descriptor = parse_candidate(view.patch_format, '1').descriptor
        assert evaluation._vector(descriptor, states, dataset=view) == [1]
        states.clear()
        assert evaluation._vector(descriptor, states, dataset=view) == []


def test_cooperative_validation_interrupts_and_does_not_retain_trust(dataset):
    class Cancelled(Exception):
        pass
    checks = 0
    def check():
        nonlocal checks
        checks += 1
        if checks == 3:
            raise Cancelled()
    with pytest.raises(Cancelled):
        with dataset.validation(check=check):
            pytest.fail('cancelled validation yielded')
    with dataset.validation() as view:
        assert view.case('function:2')['capture']['complete'] is True
        with pytest.raises(Cancelled):
            with view.validation(check=lambda: (_ for _ in ()).throw(Cancelled())):
                pytest.fail('cancelled nested operation yielded')
