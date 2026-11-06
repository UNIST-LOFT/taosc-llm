"""Original-POC diagnostics stay distinct from the oracle and candidate evidence."""
import json

import pytest

from taosc_llm.context import digest, prepare_context
from taosc_llm.dataset import canonical, load_dataset
from taosc_llm.evidence import POC_LOG_BYTES, POC_SUMMARY_BYTES, poc_diagnostic, poc_log
from test_context_tools import make_dataset, proposal, query


SEGV = """QEMU-AddressSanitizer:DEADLYSIGNAL
==38==ERROR: QEMU-AddressSanitizer: SEGV on unknown address 0x0000000000759000 (pc 0x00007ffff7459911 bp 0x12 sp 0x34 T38)
    #0 0x00007ffff7459911 in __libqasan_memset (/private/store/lib/libqasan.so+0x5911)
    #1 0x000000000045edf2 in warn (/private/build/bin/objdump+0x5edf2)

QEMU-AddressSanitizer can not provide additional info.
SUMMARY: QEMU-AddressSanitizer: in __libqasan_memset
==38==ABORTING
"""


def context_for(tmp_path, payload):
    dataset = make_dataset(tmp_path / "dataset")
    if payload is not None:
        manifest = dataset.manifest
        path = dataset.workdir / "trace" / "qasan.log"
        path.parent.mkdir()
        raw = payload.encode() if isinstance(payload, str) else payload
        path.write_bytes(raw)
        manifest["artifacts"]["trace/qasan.log"] = {
            "path": "workdir/trace/qasan.log", "sha256": digest(raw)}
        manifest.pop("dataset_id")
        manifest["dataset_id"] = digest(canonical(manifest))
        (dataset.root / "manifest.json").write_text(json.dumps(manifest))
        dataset = load_dataset(dataset.root)
    return prepare_context(dataset, run_dir=tmp_path / "run")


def private_diagnostic(context):
    with context.dataset.validation() as dataset:
        return poc_diagnostic(dataset)


def test_summary_separates_reported_memory_pc_and_oracle(tmp_path):
    context = context_for(tmp_path, SEGV)
    diagnostic = private_diagnostic(context)
    assert diagnostic["status"] == "recognized"
    assert diagnostic["error"] == "SEGV on unknown address 0x0000000000759000"
    assert diagnostic["reported_address"] == "0x759000"
    assert diagnostic["reported_pc"] == "0x7ffff7459911"
    assert diagnostic["access"] is None
    assert diagnostic["source"]["execution_binding"] == "not-recorded"
    assert diagnostic["source"]["log_sha256"] == digest(SEGV.encode())
    assert len(diagnostic["fault_stack"]) == 2
    assert "libqasan.so+0x5911" in diagnostic["fault_stack"][0]
    assert "/private/" not in context.initial_prompt()
    assert "SUMMARY: QEMU" not in context.initial_prompt()
    # A runtime library PC must not become a target reference when none exists.
    assert "system" not in context.projection["targets"]
    public = context.projection["original_poc"]["diagnostic"]
    assert public["basis"] == "saved_log"
    assert "source" not in public and digest(SEGV.encode()) not in context.initial_prompt()
    context.validate_proposal(proposal(context, decision="abstain", predicate=None,
                                      evidence_ids=[public["evidence_id"]]))
    assert context.dataset.artifact("trace/qasan.log").read_text() == SEGV


def test_allocation_stack_and_later_report_require_detail_read(tmp_path):
    log = """==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x1234 at pc 0xabcd
READ of size 8 at 0x1234 thread T0
    #0 0xabcd in fault (/secret/build/test+0x12)

freed by thread T0 here:
    #0 0x1111 in deallocator (/secret/build/test+0x34)

previously allocated by thread T0 here:
    #0 0x2222 in allocator (/secret/build/test+0x56)
==2==ERROR: AddressSanitizer: SEGV on unknown address 0x9999 (pc 0xffff)
    #0 0xffff in second_report (/secret/build/test+0x78)
"""
    context = context_for(tmp_path, log)
    diagnostic = private_diagnostic(context)
    assert diagnostic["access"] == {"operation": "READ", "size": 8}
    assert diagnostic["reported_pc"] == "0xabcd"
    assert len(diagnostic["fault_stack"]) == 1
    assert "deallocator" not in context.initial_prompt()
    assert "second_report" not in context.initial_prompt()
    page = query(context, "get_patch_context", view="poc_log")
    assert page["ok"] and "next_cursor" not in page
    assert "deallocator" in page["text"]
    assert "allocator" in page["text"]
    assert "second_report" in page["text"]
    assert "/secret/" not in json.dumps(page)
    context.validate_proposal(proposal(context, decision="abstain", predicate=None,
                                      evidence_ids=[page["evidence_id"]]))
    with pytest.raises(ValueError):
        context.validate_proposal(proposal(context, evidence_ids=["poc-log:" + "0" * 64]))


@pytest.mark.parametrize("payload,status", [(None, "missing"), (b"", "empty"),
                                           (b"qemu: interrupted\xff\n", "unrecognized")])
def test_missing_or_incomplete_diagnostic_does_not_invent_a_crash(tmp_path, payload, status):
    context = context_for(tmp_path, payload)
    diagnostic = private_diagnostic(context)
    assert diagnostic["status"] == status
    assert diagnostic["error"] is None and diagnostic["reported_pc"] is None
    assert diagnostic["fault_stack"] == []
    page = query(context, "get_patch_context", view="poc_log")
    assert page["ok"] and "next_cursor" not in page
    assert "diagnostic" not in context.projection["original_poc"]
    if payload:
        assert "interrupted" in page["text"]


def test_utf8_pages_preserve_log_and_cursors_stay_scoped(tmp_path):
    log = "".join(f"{i:04d}: 디버그 é " + "x" * 150 + "\n" for i in range(250))
    context = context_for(tmp_path, log)
    first = query(context, "get_patch_context", view="poc_log")
    assert first["next_cursor"]
    assert not query(context, "get_patch_context", cursor=first["next_cursor"])["ok"]
    mismatched = query(context, "get_function_analysis", procedure_id="procedure:0x1000",
                       view="instructions", cursor=first["next_cursor"])
    assert mismatched["error"]["code"] == "invalid_cursor"
    other = prepare_context(context.dataset, run_dir=tmp_path / "other")
    assert query(other, "get_patch_context", view="poc_log", cursor=first["next_cursor"])["error"]["code"] == "invalid_cursor"
    chunks, evidence = [], set()
    page = first
    offset = 0
    while True:
        assert page["ok"]
        detail = page
        assert detail["range"]["start"] == offset
        assert len(detail["text"].encode()) <= 8192
        assert len(detail["text"].splitlines()) <= 120
        offset += len(detail["text"].encode())
        assert detail["range"]["end"] == offset
        assert detail["evidence_id"] not in evidence
        evidence.add(detail["evidence_id"])
        chunks.append(detail["text"])
        if "next_cursor" not in page:
            break
        page = query(context, "get_patch_context", view="poc_log", cursor=page["next_cursor"])
    assert "".join(chunks) == log
    assert offset == first["total_bytes"]


@pytest.mark.parametrize("long_line", [False, True])
def test_source_limit_is_explicit_and_never_leaks_partial_paths(tmp_path, long_line):
    payload = (b"/private/" + b"x" * (POC_LOG_BYTES + 100) if long_line
               else SEGV.encode() + b"diagnostic line\n" * (POC_LOG_BYTES // 10))
    context = context_for(tmp_path, payload)
    summary = private_diagnostic(context)
    assert summary["source_truncated"] and summary["read_bytes"] <= POC_SUMMARY_BYTES
    page = query(context, "get_patch_context", view="poc_log")
    with context.dataset.validation() as dataset:
        detail = poc_log(dataset)
    assert page["ok"] and "note" in page
    assert detail["source_truncated"] and detail["read_bytes"] <= POC_LOG_BYTES
    assert detail["source_bytes"] == len(payload)
    assert "/private/" not in json.dumps(page)
    if long_line:
        assert "text" not in page and "next_cursor" not in page


def test_diagnostic_queries_reject_changed_frozen_log(tmp_path):
    context = context_for(tmp_path, SEGV)
    context.dataset.artifact("trace/qasan.log").write_text("changed")
    assert query(context, "get_patch_context", view="poc_log")["error"]["code"] == "backend_error"
    assert not query(context, "get_patch_context")["ok"]


def test_oversized_report_fields_remain_bounded_without_partial_addresses(tmp_path):
    log = ("ERROR: AddressSanitizer: SEGV on unknown address 0x" + "1" * 1000
           + " (pc 0x" + "2" * 1000 + ")\n"
           + "    #0 0x1234 in " + "symbol" * 200 + "\n")
    context = context_for(tmp_path, log)
    diagnostic = private_diagnostic(context)
    assert diagnostic["reported_address"] is None and diagnostic["reported_pc"] is None
    assert len(diagnostic["error"]) == 512 and diagnostic["error_truncated"]
    assert len(diagnostic["fault_stack"][0]) == 512 and diagnostic["stack_truncated"]
    assert query(context, "get_patch_context", view="poc_log")["text"] == log


def test_fault_stack_bound_does_not_expose_all_frames_inline(tmp_path):
    log = SEGV.split("    #0")[0] + "".join(
        f"    #{i} 0x{1000+i:x} in frame_{i} (/secret/bin/objdump+0x{i:x})\n" for i in range(12))
    context = context_for(tmp_path, log)
    diagnostic = private_diagnostic(context)
    assert len(diagnostic["fault_stack"]) == 6 and diagnostic["stack_truncated"]
    assert "frame_11" not in context.initial_prompt()
    assert "frame_11" in query(context, "get_patch_context", view="poc_log")["text"]
