"""Physical journal recovery must never invent semantic search commits."""
import hashlib
import json
import multiprocessing
import os
import stat

import pytest

from taosc_llm.no_llm import journal as module
from taosc_llm.no_llm.journal import Journal, JournalError


IDENTITY = {"dataset": "dataset-sha", "parser": "parser-v1", "limits": {"atoms": 32}}


def segments(directory):
    return sorted((directory / "segments").glob("*.jsonl"))


def snapshot(directory):
    return {str(path.relative_to(directory)): path.read_bytes()
            for path in directory.rglob("*") if path.is_file()}


def replace_bytes(path, data):
    path.chmod(0o600)
    path.write_bytes(data)
    path.chmod(0o400)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def resign(record):
    record.pop("sha256", None)
    record["sha256"] = hashlib.sha256(canonical(record)).hexdigest()
    return canonical(record) + b"\n"


def _contend(directory, connection):
    try:
        with Journal(directory, IDENTITY, resume=True):
            connection.send("entered")
    except Exception as exc:
        connection.send((type(exc).__name__, str(exc)))
    finally:
        connection.close()


def test_resume_preserves_all_old_bytes_and_payload_identity(tmp_path):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        reference = journal.store({"vector": [0, 1, 0], "unicode": "한글"})
        assert journal.store({"unicode": "한글", "vector": [0, 1, 0]}) == reference
        first = journal.append("proposal", {"evaluation": reference})
        assert first["seq"] == 1
        assert journal.load(reference) == {"vector": [0, 1, 0], "unicode": "한글"}
    old = snapshot(directory)
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert journal.events == [first]
        second = journal.append("owner_commit", {"owner": ["case-1"]})
        assert second["seq"] == 2
    assert len(segments(directory)) == 2
    assert all((directory / name).read_bytes() == data for name, data in old.items())
    for path in directory.rglob("*"):
        assert not stat.S_IMODE(path.stat().st_mode) & 0o077
    assert stat.S_IMODE((directory / reference["path"]).stat().st_mode) == 0o400
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert journal.events == [first, second]
    assert len(segments(directory)) == 3


def test_append_does_not_share_nested_event_data_with_the_caller(tmp_path):
    directory = tmp_path / "search"
    data = {"revision": {"owners": ["case-1"]}}
    with Journal(directory, IDENTITY) as journal:
        acknowledged = journal.append("owner_commit", data)
        data["revision"]["owners"].append("input-mutation")
        acknowledged["data"]["revision"]["owners"].append("return-mutation")
        expected = journal.events[0]
        assert expected["data"]["revision"]["owners"] == ["case-1"]
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert journal.events == [expected]


def test_pending_evaluation_is_not_promoted_or_rewritten(tmp_path):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        journal.append("owner_commit", {"revision": 1})
        journal.append("proposal", {"revision": 2})
        journal.append("evaluation_pending", {"revision": 2})
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert [event["kind"] for event in journal.events] == [
            "owner_commit", "proposal", "evaluation_pending"]
        assert [event["data"]["revision"] for event in journal.events
                if event["kind"] == "owner_commit"] == [1]
        journal.append("evaluation_pending", {"revision": 2, "retry": True})
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert len(journal.events) == 4
        assert sum(event["kind"] == "owner_commit" for event in journal.events) == 1


@pytest.mark.parametrize("tail", [b'{"seq":2,"kind":"owner_commit",', b'\xf0\x9f'])
def test_torn_final_tail_is_preserved_across_multiple_resumes(tmp_path, tail):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        first = journal.append("owner_commit", {"revision": 1})
    original = segments(directory)[0]
    replace_bytes(original, original.read_bytes() + tail)
    old_bytes = original.read_bytes()
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert journal.events == [first]
        assert journal.torn_tails == [original.name]
        journal.append("proposal", {"revision": 2})
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert [event["seq"] for event in journal.events] == [1, 2]
        assert journal.torn_tails == [original.name]
    assert original.read_bytes() == old_bytes
    assert len(segments(directory)) == 3


def test_complete_record_without_newline_remains_pending(tmp_path):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        journal.append("proposal", {"revision": 1})
        journal.append("owner_commit", {"revision": 1})
    path = segments(directory)[0]
    replace_bytes(path, path.read_bytes().removesuffix(b"\n"))
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert [event["kind"] for event in journal.events] == ["proposal"]
        journal.append("evaluation_pending", {"revision": 1})
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert [event["seq"] for event in journal.events] == [1, 2]
        assert not any(event["kind"] == "owner_commit" for event in journal.events)


@pytest.mark.parametrize("partial", [b"", b'{"schema":1,"segment":2'])
def test_torn_new_segment_header_recovers_without_deleting_bytes(tmp_path, partial):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        journal.append("proposal", {"revision": 1})
    interrupted = directory / "segments" / "00000002.jsonl"
    interrupted.write_bytes(partial)
    interrupted.chmod(0o400)
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert journal.torn_tails == [interrupted.name]
        journal.append("evaluation_pending", {"revision": 1})
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert [event["seq"] for event in journal.events] == [1, 2]
    assert interrupted.read_bytes() == partial


@pytest.mark.parametrize("corruption", ["middle-json", "final-json", "checksum", "sequence", "prev", "unterminated-checksum"])
def test_completed_corruption_is_rejected_without_mutation(tmp_path, corruption):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        journal.append("proposal", {"revision": 1})
        journal.append("owner_commit", {"revision": 1})
    path = segments(directory)[0]
    lines = path.read_bytes().splitlines(keepends=True)
    if corruption == "middle-json":
        lines[1] = b'{"broken":\n'
    elif corruption == "final-json":
        lines[-1] = b'{"broken":\n'
    else:
        record = json.loads(lines[-1])
        if corruption in {"checksum", "unterminated-checksum"}:
            record["data"] = {"revision": 99}
            lines[-1] = canonical(record) + (b"" if corruption.startswith("unterminated") else b"\n")
        elif corruption == "sequence":
            record["seq"] = 99
            lines[-1] = resign(record)
        else:
            record["prev"] = "0" * 64
            lines[-1] = resign(record)
    replace_bytes(path, b"".join(lines))
    old = snapshot(directory)
    failed = Journal(directory, IDENTITY, resume=True)
    with pytest.raises(JournalError):
        failed.__enter__()
    assert failed._fds == []
    assert snapshot(directory) == old


def test_corruption_of_previously_recovered_torn_tail_is_not_ignored(tmp_path):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        journal.append("proposal", {})
    first = segments(directory)[0]
    replace_bytes(first, first.read_bytes() + b'{"partial":')
    with Journal(directory, IDENTITY, resume=True):
        pass
    replace_bytes(first, first.read_bytes() + b"1")
    old = snapshot(directory)
    with pytest.raises(JournalError, match="chain"):
        with Journal(directory, IDENTITY, resume=True):
            pass
    assert snapshot(directory) == old


def test_identity_mismatch_fails_before_lock_or_output_mutation(tmp_path, monkeypatch):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY):
        pass
    old = snapshot(directory)
    real_open = module.os.open

    def no_writes(path, flags, *args, **kwargs):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)
        return real_open(path, flags, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(module.os, "open", no_writes)
        with pytest.raises(JournalError, match="identity mismatch"):
            with Journal(directory, {**IDENTITY, "parser": "different"}, resume=True):
                pass
    assert snapshot(directory) == old
    with Journal(directory, IDENTITY, resume=True):
        pass


def test_single_writer_lock_rejects_process_and_same_process_contenders(tmp_path):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY):
        with pytest.raises(JournalError, match="active writer"):
            with Journal(directory, IDENTITY, resume=True):
                pass
        with pytest.raises(FileExistsError):
            with Journal(directory, IDENTITY):
                pass
        context = multiprocessing.get_context("fork")
        reader, writer = context.Pipe(duplex=False)
        process = context.Process(target=_contend, args=(directory, writer))
        process.start()
        writer.close()
        try:
            assert reader.poll(10), "contending writer failed to return"
            result = reader.recv()
            assert result[0] == "JournalError"
            assert "active writer" in result[1]
        finally:
            reader.close()
            process.join(10)
            if process.is_alive():
                process.terminate()
                process.join()
        assert process.exitcode == 0
    with Journal(directory, IDENTITY, resume=True):
        pass


def test_binary_payload_is_durable_content_addressed_and_immutable(tmp_path):
    directory = tmp_path / "search"
    data = b"\x00\xffBRCH\n\x80"
    with Journal(directory, IDENTITY) as journal:
        reference = journal.store_bytes(data, suffix=".brch")
        assert reference["sha256"] == hashlib.sha256(data).hexdigest()
        assert (directory / reference["path"]).read_bytes() == data
        assert journal.store_bytes(data, suffix=".brch") == reference
        journal.append("capture", {"bytes": reference})
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert journal.events[0]["data"]["bytes"] == reference
        assert journal.store_bytes(data, suffix=".brch") == reference
    assert (directory / reference["path"]).read_bytes() == data


def test_payload_publication_never_overwrites_a_racing_file(tmp_path, monkeypatch):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        real_publish = module._publish
        victim = None

        def race(parent, temporary, name):
            nonlocal victim
            victim = directory / "payloads" / name
            victim.write_bytes(b"racing-file")
            victim.chmod(0o400)
            real_publish(parent, temporary, name)

        with monkeypatch.context() as patch:
            patch.setattr(module, "_publish", race)
            with pytest.raises(JournalError, match="checksum"):
                journal.store({"value": 1})
        assert victim.read_bytes() == b"racing-file"
        assert not list((directory / "payloads").glob(".pending-*"))


def test_unpublished_payload_from_a_killed_writer_does_not_block_reuse(tmp_path):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY):
        pass
    pending = directory / "payloads" / ".pending-interrupted"
    pending.write_bytes(b'{"partial":')
    pending.chmod(0o400)
    with Journal(directory, IDENTITY, resume=True) as journal:
        reference = journal.store({"value": 1})
        journal.append("evaluation", {"payload": reference})
    assert pending.read_bytes() == b'{"partial":'
    assert (directory / reference["path"]).stat().st_nlink == 1
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert journal.load(reference) == {"value": 1}


def test_missing_referenced_payload_rejects_resume_before_new_segment(tmp_path):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        reference = journal.store({"vector": [1]})
        journal.append("evaluation", {"evidence": reference})
    (directory / reference["path"]).unlink()
    old = snapshot(directory)
    with pytest.raises(JournalError, match="missing"):
        with Journal(directory, IDENTITY, resume=True):
            pass
    assert snapshot(directory) == old


def test_payload_tampering_rejected_on_load_store_and_resume(tmp_path):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        reference = journal.store({"outcome": "normal"})
        journal.append("evaluation", {"evidence": reference})
        replace_bytes(directory / reference["path"], b'{"outcome":"target_crash"}')
        with pytest.raises(JournalError, match="checksum"):
            journal.load(reference)
        with pytest.raises(JournalError, match="checksum"):
            journal.store({"outcome": "normal"})
    old = snapshot(directory)
    with pytest.raises(JournalError, match="checksum"):
        with Journal(directory, IDENTITY, resume=True):
            pass
    assert snapshot(directory) == old


@pytest.mark.parametrize("path", ["../secret.json", "/tmp/secret.json", "payloads/../secret.json",
                                  "payloads/nested/secret.json", "payloads/" + "0" * 64 + ".json"])
def test_payload_reference_escape_and_name_digest_mismatch(tmp_path, path):
    with Journal(tmp_path / "search", IDENTITY) as journal:
        reference = journal.store({"secret": 1})
        with pytest.raises(JournalError):
            journal.load({**reference, "path": path})
        with pytest.raises(JournalError):
            journal.store_bytes(b"unsafe", suffix="/../../outside")
        with pytest.raises(JournalError):
            journal.store_bytes(b"unsafe", suffix=".json/../../outside")


def test_external_artifact_metadata_is_not_an_owned_payload_reference(tmp_path):
    directory = tmp_path / "search"
    metadata = {"path": "/external/frozen-artifact", "sha256": "a" * 64}
    with Journal(directory, IDENTITY) as journal:
        journal.append("artifact", {"artifact": metadata})
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert journal.events[0]["data"]["artifact"] == metadata


def test_payload_symlink_and_hardlink_substitutions_are_rejected(tmp_path):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        reference = journal.store({"secret": 1})
        payload = directory / reference["path"]
        outside = tmp_path / "outside.json"
        outside.write_bytes(payload.read_bytes())
        outside.chmod(0o400)
        payload.unlink()
        payload.symlink_to(outside)
        with pytest.raises(JournalError):
            journal.load(reference)
        with pytest.raises(JournalError):
            journal.store({"secret": 1})
        payload.unlink()
        os.link(outside, payload)
        with pytest.raises(JournalError, match="linked"):
            journal.load(reference)


@pytest.mark.parametrize("component", ["root", "ancestor", "segments", "payloads", "identity", "lock"])
def test_symlinked_storage_components_are_never_followed(tmp_path, component):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY):
        pass
    outside = tmp_path / "outside"
    if component == "root":
        directory.rename(outside)
        directory.symlink_to(outside, target_is_directory=True)
    elif component == "ancestor":
        parent = tmp_path / "alias"
        parent.symlink_to(tmp_path, target_is_directory=True)
        directory = parent / "search"
    else:
        name = {"identity": "identity.json", "lock": ".writer.lock"}.get(component, component)
        target = directory / name
        target.rename(outside)
        target.symlink_to(outside, target_is_directory=outside.is_dir())
    with pytest.raises((OSError, JournalError)):
        with Journal(directory, IDENTITY, resume=True):
            pass


@pytest.mark.parametrize("entry", ["run.json", "manual.txt", "cache-symlink"])
def test_new_output_rejects_unrelated_results_and_symlink_cache(tmp_path, entry):
    directory = tmp_path / "search"
    directory.mkdir()
    if entry == "cache-symlink":
        (directory / "cache").symlink_to(tmp_path, target_is_directory=True)
    else:
        (directory / entry).write_text("existing")
    with pytest.raises((FileExistsError, JournalError)):
        with Journal(directory, IDENTITY):
            pass
    assert not (directory / ".writer.lock").exists()


def test_new_output_allows_existing_real_cache(tmp_path):
    directory = tmp_path / "search"
    cache = directory / "cache"
    cache.mkdir(parents=True)
    (cache / "evidence").write_bytes(b"cached")
    with Journal(directory, IDENTITY):
        pass
    assert (cache / "evidence").read_bytes() == b"cached"


def test_initial_reservation_race_never_removes_another_creators_lock(tmp_path, monkeypatch):
    directory = tmp_path / "search"
    directory.mkdir()
    real_open = module.os.open
    competing = None

    def race(path, flags, *args, **kwargs):
        nonlocal competing
        if path == ".writer.lock" and flags & os.O_EXCL:
            competing = real_open(path, flags, *args, **kwargs)
        return real_open(path, flags, *args, **kwargs)

    failed = Journal(directory, IDENTITY)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(module.os, "open", race)
            with pytest.raises(FileExistsError):
                failed.__enter__()
        assert (directory / ".writer.lock").exists()
        assert failed._fds == []
        assert not (directory / "identity.json").exists()
    finally:
        if competing is not None:
            os.close(competing)


@pytest.mark.parametrize("failure", ["identity-write", "segment-write", "fsync"])
def test_failed_initial_enter_cleans_owned_files_and_releases_descriptors(tmp_path, monkeypatch, failure):
    directory = tmp_path / "search"
    cache = directory / "cache"
    cache.mkdir(parents=True)
    (cache / "evidence").write_bytes(b"keep")
    failed = Journal(directory, IDENTITY)
    real_write = module._write_all

    def fail_write(fd, data):
        if (failure == "identity-write" and b'"identity"' in data
                or failure == "segment-write" and b'"segment"' in data):
            os.write(fd, data[:5])
            raise OSError("injected write failure")
        return real_write(fd, data)

    with monkeypatch.context() as patch:
        patch.setattr(module, "_write_all", fail_write)
        if failure == "fsync":
            def fail_sync(fd):
                raise OSError("injected fsync failure")
            patch.setattr(module.os, "fsync", fail_sync)
        with pytest.raises(OSError, match="injected"):
            failed.__enter__()
    assert failed._fds == []
    assert sorted(path.name for path in directory.iterdir()) == ["cache"]
    assert (cache / "evidence").read_bytes() == b"keep"
    with Journal(directory, IDENTITY):
        pass


def test_failed_resume_enter_releases_lock_and_retains_old_bytes(tmp_path, monkeypatch):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        journal.append("proposal", {})
    old = snapshot(directory)
    failed = Journal(directory, IDENTITY, resume=True)
    with monkeypatch.context() as patch:
        def fail_write(fd, data):
            os.write(fd, data[:4])
            raise OSError("injected failure")
        patch.setattr(module, "_write_all", fail_write)
        with pytest.raises(OSError, match="injected"):
            failed.__enter__()
    assert failed._fds == []
    assert snapshot(directory) == old
    with Journal(directory, IDENTITY, resume=True):
        pass


def test_failed_append_poisoning_requires_a_fresh_resume(tmp_path, monkeypatch):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        journal.append("proposal", {})
        with monkeypatch.context() as patch:
            def fail_write(fd, data):
                os.write(fd, data[:7])
                raise OSError("injected append failure")
            patch.setattr(module, "_write_all", fail_write)
            with pytest.raises(OSError):
                journal.append("owner_commit", {})
        with pytest.raises(RuntimeError, match="healthy"):
            journal.append("owner_commit", {})
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert [event["kind"] for event in journal.events] == ["proposal"]
        journal.append("evaluation_pending", {})


@pytest.mark.parametrize("corruption", ["sequence", "prev", "kind", "reference"])
def test_unterminated_complete_event_validates_structure_and_references(tmp_path, corruption):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        journal.append("proposal", {})
        journal.append("owner_commit", {})
    path = segments(directory)[0]
    lines = path.read_bytes().splitlines(keepends=True)
    record = json.loads(lines[-1])
    if corruption == "sequence":
        record["seq"] = 99
    elif corruption == "prev":
        record["prev"] = "0" * 64
    elif corruption == "kind":
        record["kind"] = ""
    else:
        record["data"] = {"state": {"path": "payloads/" + "0" * 64 + ".json",
                                    "sha256": "0" * 64}}
    lines[-1] = resign(record).removesuffix(b"\n")
    replace_bytes(path, b"".join(lines))
    old = snapshot(directory)
    with pytest.raises(JournalError):
        with Journal(directory, IDENTITY, resume=True):
            pass
    assert snapshot(directory) == old


def test_unterminated_complete_segment_header_is_not_exempt_from_chain_validation(tmp_path):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY):
        pass
    original = segments(directory)[0]
    header = json.loads(original.read_bytes())
    header["segment"] = 99
    interrupted = directory / "segments" / "00000002.jsonl"
    interrupted.write_bytes(resign(header).removesuffix(b"\n"))
    interrupted.chmod(0o400)
    old = snapshot(directory)
    with pytest.raises(JournalError, match="chain"):
        with Journal(directory, IDENTITY, resume=True):
            pass
    assert snapshot(directory) == old


@pytest.mark.parametrize("tail", [b"not-json", b'{"x":oops', b'{"x":"\\q',
                                  b'{"x":"\\u0z', b'{"x":1e+}', b'\xff'])
def test_malformed_tail_without_newline_is_not_treated_as_interruption(tmp_path, tail):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY):
        pass
    path = segments(directory)[0]
    replace_bytes(path, path.read_bytes() + tail)
    old = snapshot(directory)
    with pytest.raises(JournalError):
        with Journal(directory, IDENTITY, resume=True):
            pass
    assert snapshot(directory) == old


@pytest.mark.parametrize("tail", [b'{"x":tru', b'{"x":-', b'{"x":1e+', b'{"x":1.',
                                  b'{"x":"\\u00', b'{"x":"\\', b'{"x":"\xf0\x9f'])
def test_syntactically_incomplete_tail_remains_recoverable(tmp_path, tail):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        committed = journal.append("owner_commit", {"revision": 1})
    path = segments(directory)[0]
    replace_bytes(path, path.read_bytes() + tail)
    old = path.read_bytes()
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert journal.events == [committed]
        assert journal.torn_tails == [path.name]
    assert path.read_bytes() == old


@pytest.mark.parametrize("damage", ["missing", "checksum"])
@pytest.mark.parametrize("absolute_capture", [False, True])
def test_resume_authenticates_transitive_state_and_evaluation_references(tmp_path, damage, absolute_capture):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        capture = journal.store_bytes(b"full-vector", suffix=".brch")
        if absolute_capture:
            capture = {**capture, "path": str(directory / capture["path"])}
        evaluation = journal.store({"cases": [{"capture": capture}]})
        state = journal.store({"evaluation": evaluation, "owners": ["case-1"]})
        journal.append("commit", {"state": state})
    capture_path = directory / capture["path"]
    if damage == "missing":
        capture_path.unlink()
    else:
        replace_bytes(capture_path, b"different-vector")
    old = snapshot(directory)
    with pytest.raises(JournalError, match=damage):
        with Journal(directory, IDENTITY, resume=True):
            pass
    assert snapshot(directory) == old


def test_load_and_append_reject_dangling_nested_evidence(tmp_path):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        capture = journal.store_bytes(b"capture", suffix=".brch")
        state = journal.store({"evaluation": {"captures": [capture]}})
        (directory / capture["path"]).unlink()
        with pytest.raises(JournalError, match="missing"):
            journal.load(state)
        with pytest.raises(JournalError, match="missing"):
            journal.append("commit", {"state": state})
        assert journal.events == []


def test_failed_payload_directory_sync_cannot_be_bypassed_by_deduplication(tmp_path, monkeypatch):
    directory = tmp_path / "search"
    payload = {"vector": [1]}
    with Journal(directory, IDENTITY) as journal:
        real_sync = module.os.fsync

        def fail_directory_sync(fd):
            if fd == journal._payloads:
                raise OSError("injected payload directory sync failure")
            real_sync(fd)

        with monkeypatch.context() as patch:
            patch.setattr(module.os, "fsync", fail_directory_sync)
            with pytest.raises(OSError, match="directory sync"):
                journal.store(payload)
        with pytest.raises(RuntimeError, match="healthy"):
            journal.store(payload)
        with pytest.raises(RuntimeError, match="healthy"):
            journal.append("commit", {})
    with Journal(directory, IDENTITY, resume=True) as journal:
        reference = journal.store(payload)
        journal.append("commit", {"evaluation": reference})
    with Journal(directory, IDENTITY, resume=True) as journal:
        assert journal.load(journal.events[0]["data"]["evaluation"]) == payload


def test_payload_and_commit_fsync_order_is_observable(tmp_path, monkeypatch):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        operations = []
        real_write, real_sync, real_publish = module._write_all, module.os.fsync, module._publish
        payload_fd = None

        def write(fd, data):
            nonlocal payload_fd
            if fd == journal._segment:
                operations.append("event-write")
            else:
                payload_fd = fd
                operations.append("payload-write")
            real_write(fd, data)

        def sync(fd):
            if fd == journal._payloads:
                operations.append("payload-directory-sync")
            elif fd == journal._segment:
                operations.append("event-sync")
            elif fd == payload_fd:
                operations.append("payload-sync")
            real_sync(fd)

        def publish(parent, temporary, name):
            operations.append("publish")
            real_publish(parent, temporary, name)

        with monkeypatch.context() as patch:
            patch.setattr(module, "_write_all", write)
            patch.setattr(module.os, "fsync", sync)
            patch.setattr(module, "_publish", publish)
            reference = journal.store({"vector": [1]})
            journal.append("commit", {"evaluation": reference})
        assert operations == ["payload-write", "payload-sync", "publish",
                              "payload-directory-sync", "event-write", "event-sync"]


def test_resume_syncs_recovered_dependencies_before_writing_new_segment(tmp_path, monkeypatch):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        reference = journal.store({"vector": [1]})
        journal.append("commit", {"evaluation": reference})
    paths = [directory, directory / "segments", directory / "payloads",
             directory / "identity.json", segments(directory)[0], directory / reference["path"]]
    required = {(path.stat().st_dev, path.stat().st_ino) for path in paths}
    synced = set()
    real_sync, real_write = module.os.fsync, module._write_all

    def sync(fd):
        info = os.fstat(fd)
        synced.add((info.st_dev, info.st_ino))
        real_sync(fd)

    def write(fd, data):
        assert required <= synced
        real_write(fd, data)

    with monkeypatch.context() as patch:
        patch.setattr(module.os, "fsync", sync)
        patch.setattr(module, "_write_all", write)
        with Journal(directory, IDENTITY, resume=True) as journal:
            assert len(journal.events) == 1


def test_replacing_named_lock_cannot_admit_a_concurrent_writer(tmp_path):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        lock = directory / ".writer.lock"
        lock.rename(directory / ".displaced-lock")
        lock.write_bytes(b"")
        lock.chmod(0o600)
        with pytest.raises(JournalError, match="active writer"):
            with Journal(directory, IDENTITY, resume=True):
                pass
        with pytest.raises(JournalError, match="replaced"):
            journal.append("commit", {})
        assert len(segments(directory)) == 1


@pytest.mark.parametrize("component", ["root", "segments", "payloads", "identity", "segment"])
def test_active_writer_rejects_symlink_storage_substitution(tmp_path, component):
    directory = tmp_path / "search"
    with Journal(directory, IDENTITY) as journal:
        original = segments(directory)[0]
        old = original.read_bytes()
        if component == "root":
            target = directory
        elif component == "identity":
            target = directory / "identity.json"
        elif component == "segment":
            target = original
        else:
            target = directory / component
        moved = target.with_name(target.name + "-displaced")
        target.rename(moved)
        target.symlink_to(moved, target_is_directory=moved.is_dir())
        with pytest.raises(JournalError):
            journal.append("commit", {})
        with pytest.raises(RuntimeError, match="healthy"):
            journal.store({"evaluation": "not-published"})
        assert original.read_bytes() == old
