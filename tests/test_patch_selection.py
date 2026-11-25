"""Single-first selector contracts; no native build or target execution."""
import hashlib
import json
from pathlib import Path
import pytest

from taosc_llm import patch as selector
from taosc_llm.patch import SelectionError


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    return path


def _identity(run: Path, *, location="0x401a82", **changes) -> Path:
    value = {"schema_version": 1, "kind": "original-only-minimizer", "binary": "fixture",
             "original_sha256": _sha(b"original"), "invocation": ["@@"],
             "patch_location": location,
             "poc": {"path": "input/poc/poc", "sha256": _sha(b"malicious")}, **changes}
    return _write(run / "original-identity.json", json.dumps(value))


def _case(case_id: int, filename: str, data: bytes, *, exit_info="crash",
          fault="401c30", location="401a82", hits=1) -> str:
    return (f"[testcase] [original-result] [id {case_id}] [file {filename}] "
            f"[input-sha256 {_sha(data)}] [version 4] [exit {exit_info}] "
            f"[patch-loc {location}] [func-entry 4018c0] [patch-hit {hits}] [func-hit 1] "
            f"[fault-addr {fault if exit_info == 'crash' else 0}] "
            f"[tracer-fault-valid false] [tracer-fault-source unavailable] "
            f"[tracer-fault-addr 0] [tracer-fault-image none] [tracer-fault-image-offset 0] "
            f"[memcheck-policy unavailable] [patch-func-candidates [4018c0:1]] "
            f"[stacktrace []] [concrete-oracle qasan-main-v2] "
            f"[concrete-fault-valid {'true' if exit_info == 'crash' else 'false'}] "
            f"[raw-fault-addr {fault if exit_info == 'crash' else 0}] [concrete-fault-source "
            f"{'native' if exit_info == 'crash' else 'unavailable'}] [time 1]")


@pytest.fixture
def subject(tmp_path):
    subject = tmp_path / "subject"
    subject.mkdir()
    _write(subject / "config.env", "POC_INPUT=input/poc/poc\nPOC_DIR=input/poc\n"
                                   "BINARY=fixture\nTEST_CMD=@@\n")
    source = subject / "workdir"
    _write(source / "args", "fixture @@\n")
    _write(source / "poc", "poc")
    _write(source / "input/poc/poc", b"malicious")
    _write(source / "poc-exit-code", "139\n")
    _write(source / "source-binary", "/store/fixture\n")
    _write(source / "fixture.orig", b"original")
    _write(source / "original-sha256", _sha(b"original") + "\n")
    _write(source / "patch-candidates", "401a82 401a1f 401b59\n")
    _write(source / "patch-location", "401a82\n")
    _write(source / "destinations", "401a1f\n401b59\n")
    _write(source / "patch-destination", "401a1f\n")
    _write(source / "trace/crash.address", "401c30\n")
    _write(source / "trace/qasan.log", "#0 0x401c30 in crash\n")
    _write(source / "generate-concrete.env",
           'BINARY="fixture"\nTEST_CMD="@@ "\nPATCH_LOC="0x401a82"\n'
           'POC_INPUT="input/poc/poc"\nPOC_DIR="input/poc"\n')
    run = source / "out" / "br-gen-con-00000"
    _write(run / "minimized/0_first", b"malicious")
    _write(run / "minimized/1_second", b"normal")
    _write(run / "minimizer.sbsv", "\n".join([
        "[minimizer] [baseline] [version 1] [baseline original]",
        _case(0, "0_first", b"malicious"),
        _case(1, "1_second", b"normal", exit_info="ok"),
        "[minimizer] [done]",
        "",
    ]))
    _identity(run)
    return subject, source, run


def test_metadata_accepts_common_preparation_without_stage_marker(subject):
    _, source, _ = subject
    metadata = selector._metadata(source)
    assert metadata["binary"] == "fixture"
    assert metadata["location_text"] == "0x401a82"
    assert metadata["destination"] == 0x401a1f
    assert metadata["destinations"] == [0x401a1f, 0x401b59]
    assert metadata["candidates"][0x401a82] == [0x401a1f, 0x401b59]


def test_metadata_retains_actionless_scout_site_beside_selected_association(subject):
    _, source, _ = subject
    _write(source / "patch-candidates", "40118e\n401a82 401a1f 401b59\n")
    metadata = selector._metadata(source)
    assert metadata["candidates"] == {0x40118e: [], 0x401a82: [0x401a1f, 0x401b59]}
    _write(source / "patch-candidates", "40118e 401a1f\n401a82\n")
    with pytest.raises(SelectionError, match="absent from patch-candidates"):
        selector._metadata(source)


@pytest.mark.parametrize("row", ["not-an-address", "0", "-1", "10000000000000000",
                                  "40118e not-an-action", "40118e -1"])
def test_actionless_scout_support_does_not_accept_malformed_addresses(subject, row):
    _, source, _ = subject
    _write(source / "patch-candidates", row + "\n401a82 401a1f 401b59\n")
    with pytest.raises(SelectionError, match="invalid patch-candidates row"):
        selector._metadata(source)


def test_metadata_rejects_unassociated_site_or_action(subject):
    _, source, _ = subject
    _write(source / "destinations", "401b59\n")
    _write(source / "patch-destination", "401b59\n")
    metadata = selector._metadata(source)
    assert metadata["destination"] == 0x401b59
    _write(source / "patch-destination", "401fff\n")
    _write(source / "destinations", "401fff\n")
    with pytest.raises(SelectionError, match="absent from patch-candidates"):
        selector._metadata(source)


def test_metadata_rejects_noncurrent_original(subject):
    _, source, _ = subject
    _write(source / "fixture.orig", b"rebuilt")
    with pytest.raises(SelectionError, match="original hash mismatch"):
        selector._metadata(source)


@pytest.mark.parametrize("terminal,expected", [("done", "done"),
                                               ("stopped", "wall-time-reached")])
def test_concrete_corpus_requires_current_terminal_marker(subject, terminal, expected):
    _, _, run = subject
    text = (run / "minimizer.sbsv").read_text().replace(
        "[minimizer] [done]",
        "[minimizer] [done]" if terminal == "done"
        else "[minimizer] [stopped] [reason wall-time-reached]")
    _write(run / "minimizer.sbsv", text)
    rows, marker = selector._concrete_rows(run, 0x401a82, check_inputs=True)
    assert marker == expected and len(rows) == 2
    _write(run / "minimizer.sbsv", text.replace("[minimizer] [done]", "")
           .replace("[minimizer] [stopped] [reason wall-time-reached]", ""))
    with pytest.raises(SelectionError, match="completed minimizer marker"):
        selector._concrete_rows(run, 0x401a82, check_inputs=True)


@pytest.mark.parametrize("field,value", [
    ("[patch-loc 401a82]", "[patch-loc 401000]"),
    ("[patch-hit 1]", "[patch-hit 0]"),
    ("[concrete-oracle qasan-main-v2]", "[concrete-oracle unknown]"),
])
def test_concrete_corpus_rejects_wrong_site_hit_oracle_or_fault(subject, field, value):
    _, _, run = subject
    text = (run / "minimizer.sbsv").read_text().replace(field, value, 1)
    _write(run / "minimizer.sbsv", text)
    with pytest.raises(SelectionError):
        selector._concrete_rows(run, 0x401a82, check_inputs=True)


def test_concrete_corpus_rejects_changed_inputs_and_duplicates(subject):
    _, _, run = subject
    _write(run / "minimized/0_first", b"changed")
    with pytest.raises(SelectionError, match="identity changed"):
        selector._concrete_rows(run, 0x401a82, check_inputs=True)
    _write(run / "minimized/0_first", b"malicious")
    text = (run / "minimizer.sbsv").read_text()
    row = text.splitlines()[1]
    _write(run / "minimizer.sbsv", text.replace(row, row + "\n" + row))
    with pytest.raises(SelectionError, match="duplicate concrete case"):
        selector._concrete_rows(run, 0x401a82, check_inputs=True)


def test_concrete_identity_changes_with_terminal_kind(subject):
    _, source, run = subject
    concrete = selector._concrete(run, selector._metadata(source))
    assert concrete["terminal"] == "done" and concrete["cases"] == 2
    changed = (run / "minimizer.sbsv").read_text().replace(
        "[minimizer] [done]", "[minimizer] [stopped] [reason wall-time-reached]")
    _write(run / "minimizer.sbsv", changed)
    other = selector._concrete(run, selector._metadata(source))
    assert other["terminal"] == "wall-time-reached"
    assert other["cases_sha256"] != concrete["cases_sha256"]


def test_single_family_selection_respects_signal_and_site():
    crash = {"exit_code": 139, "location": 0x401c30, "crash": 0x401c30}
    assert selector._single_family(crash, False) == "Single CWE-823"
    assert selector._single_family(crash, True) == "Single CWE-805"
    assert selector._single_family({**crash, "location": 0x401a82}, False) is None
    assert selector._single_family({"exit_code": 136, "location": 1, "crash": 1}, False) == "Single CWE-369"
    assert selector._single_family({"exit_code": 134, "location": 1, "crash": 1}, False) == "Single CWE-617"
    assert selector._erm_family(True) == "ERM CWE-805"
    assert selector._erm_family(False) == "ERM generic"


def _fake_selection(root: Path, *, kind="single", terminal="done") -> dict:
    binary = "fixture"
    _write(root / "fixture.orig", b"original")
    for name in ("fixture.brpatched", "fixture.brpatched.json"):
        _write(root / name, name.encode())
    environment = ('BINARY="fixture"\nTEST_CMD="@@"\nPATCH_LOC="0x401a82"\n'
                   'POC_INPUT="input/poc/poc"\nPOC_DIR="input/poc"\n')
    _write(root / "generate-concrete.env", environment)
    source = root.with_name(root.name + "-source")
    source_files = {
        "fixture.orig": b"original", "args": "fixture @@\n", "poc": "poc\n",
        "poc-exit-code": "134\n", "source-binary": "/store/fixture\n",
        "original-sha256": _sha(b"original") + "\n",
        "patch-candidates": "401a82 401a1f\n", "patch-location": "401a82\n",
        "destinations": "401a1f\n", "patch-destination": "401a1f\n",
        "generate-concrete.env": environment, "trace/crash.address": "401c30\n",
        "trace/qasan.log": "#0 0x401c30 in crash\n", "input/poc/poc": b"malicious",
    }
    for name, content in source_files.items():
        _write(source / name, content)
    _write(source / "config.env", environment)
    _write(root / "patch-selection.json", "{}")
    artifacts = {}
    for path in sorted(root.iterdir()):
        if path.is_file() and path.name != "patch-selection.json":
            artifacts[path.name] = {"path": path.name, "sha256": _sha(path.read_bytes())}
    evaluation = _write(root / "evaluation.json", '{"status":"accepted"}')
    artifacts["evaluation.json"] = {"path": "evaluation.json",
                                    "sha256": _sha(evaluation.read_bytes())}
    trial = _write(root / "trials/000-cwe-617/evaluation.json",
                   '{"status":"accepted"}')
    artifacts["trials/000-cwe-617/evaluation.json"] = {
        "path": "trials/000-cwe-617/evaluation.json",
        "sha256": _sha(trial.read_bytes())}
    value = {"schema_version": 1, "kind": "single-first-selection", "status": "selected",
             "selection": kind, "binary": binary,
             "trials": [{"family": "Single CWE-617", "destination": "0x401a1f",
                         "status": "accepted", "reason": None,
                         "evaluation": artifacts["trials/000-cwe-617/evaluation.json"]}],
             "patch_format": "Single CWE-617" if kind == "single" else "ERM generic",
             "patch_location": "0x401a82", "patch_destination": "0x401a1f",
             "concrete_run": str(root / "concrete"),
             "concrete": {"path": str(root / "concrete"), "minimizer_sha256": "",
                          "location": "0x401a82", "binary": binary,
                          "original_sha256": _sha(b"original"), "cases": 1,
                          "terminal": terminal, "cases_sha256": ""},
             "source": {"workdir": str(source), "original_sha256": _sha(b"original"),
                        "exit_code": 134, "allocator": False,
                        "configuration": {"subject": str(source),
                                          "artifact": selector._reference(source, source / "config.env")},
                        "artifacts": selector._source_references(source, binary)},
             "artifacts": artifacts,
             "verified": False, "binradar_verification": "not_run"}
    if kind == "single":
        value["evaluation"] = artifacts["evaluation.json"]
        value["publication"] = {"kind": "single-patch", "status": "published",
                                "artifact": artifacts["fixture.brpatched"],
                                "patch_format": value["patch_format"],
                                "patch_location": value["patch_location"],
                                "patch_destination": value["patch_destination"],
                                "verified": False, "binradar_verification": "not_run"}
    return value


def _fake_concrete(root: Path, value: dict) -> None:
    run = root / "concrete"
    _write(run / "fixture.orig", b"original")
    _write(run / "minimized/0_first", b"malicious")
    _write(run / "minimizer.sbsv", "\n".join([
        "[minimizer] [baseline] [version 1] [baseline original]",
        _case(0, "0_first", b"malicious"),
        "[minimizer] [done]" if value["concrete"]["terminal"] == "done"
        else "[minimizer] [stopped] [reason wall-time-reached]",
        "",
    ]))
    _identity(run)
    value["concrete"]["identity"] = selector._reference(run, run / "original-identity.json")
    rows, terminal = selector._concrete_rows(run, 0x401a82, check_inputs=True)
    value["concrete"].update(minimizer_sha256=_sha((run / "minimizer.sbsv").read_bytes()),
                             cases=len(rows), cases_sha256=selector._case_digest(rows, terminal))
    value["source_concrete"] = dict(value["concrete"])


def test_selection_authentication_rejects_changed_artifacts_and_corpus(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    value = _fake_selection(root)
    _fake_concrete(root, value)
    _write(root / "patch-selection.json", json.dumps(value))
    assert selector.load_patch_selection(root)["selection"] == "single"

    _write(root / "fixture.brpatched", b"tampered")
    with pytest.raises(SelectionError, match="checksum mismatch"):
        selector.load_patch_selection(root)
    _write(root / "fixture.brpatched", b"fixture.brpatched")
    _write(root / "concrete/minimized/0_first", b"changed")
    with pytest.raises(SelectionError, match="identity changed"):
        selector.load_patch_selection(root)


@pytest.mark.parametrize("missing", ["source_concrete", "source", "source.artifacts",
                                      "both", "empty-artifacts", "partial-artifacts"])
def test_selection_authentication_rejects_old_or_incomplete_source_binding(tmp_path, missing):
    root = tmp_path / "selected"
    root.mkdir()
    value = _fake_selection(root)
    _fake_concrete(root, value)
    if missing in ("source_concrete", "both"):
        del value["source_concrete"]
    if missing == "source":
        del value["source"]
    elif missing in ("source.artifacts", "both"):
        del value["source"]["artifacts"]
    elif missing == "empty-artifacts":
        value["source"]["artifacts"] = {}
    elif missing == "partial-artifacts":
        del value["source"]["artifacts"]["fixture.orig"]
    _write(root / "patch-selection.json", json.dumps(value))
    with pytest.raises(SelectionError, match="source concrete identity|source preparation identit"):
        selector.load_patch_selection(root)


def test_selection_authentication_rejects_format_and_verification_lies(tmp_path):
    root = tmp_path / "selected"
    root.mkdir()
    value = _fake_selection(root)
    _fake_concrete(root, value)
    value["verified"] = True
    _write(root / "patch-selection.json", json.dumps(value))
    with pytest.raises(SelectionError, match="verification"):
        selector.load_patch_selection(root)
    value["verified"] = False
    value["patch_format"] = "ERM generic"
    _write(root / "patch-selection.json", json.dumps(value))
    with pytest.raises(SelectionError, match="ERM format"):
        selector.load_patch_selection(root)


@pytest.mark.parametrize("argv,error", [
    ([], "--workdir"),
    (["--workdir", "w"], "--concrete-run"),
])
def test_cli_requires_explicit_preparation_and_corpus(tmp_path, argv, error):
    with pytest.raises(SystemExit) as raised:
        selector.parse_args(["--subject", str(tmp_path), *argv])
    assert raised.value.code == 2


def test_cli_defaults_output_beside_workdir(tmp_path):
    args = selector.parse_args(["--subject", str(tmp_path), "--workdir", str(tmp_path / "w"),
                               "--concrete-run", str(tmp_path / "c")])
    assert args.output == tmp_path / "w-patch"
    with pytest.raises(SystemExit):
        selector.parse_args(["--subject", str(tmp_path), "--workdir", str(tmp_path / "w"),
                             "--concrete-run", str(tmp_path / "c"), "--workers", "33"])


class FakeBackend:
    """Record selector calls; never build or execute a real patch."""

    def __init__(self, tmp_path, *, mode="accept", setup_rejected=(),
                 reject_actions=(), nonhits=()):
        self.tmp_path = tmp_path
        self.mode = mode
        self.setup_rejected = set(setup_rejected)
        self.reject_actions = set(reject_actions)
        self.nonhits = set(nonhits)
        self.stages = []
        self.setups = []
        self.observations = []

    def stage(self, workdir, format_text, location, destination, timeout, environment):
        self.stages.append((Path(workdir).name, format_text, location, destination))
        built = not format_text.startswith("ERM ")
        marker = {"schema_version": 1, "kind": "taosc-patch-stage",
                  "status": "built" if built else "prepared",
                  "binary": "fixture", "patch_format": format_text,
                  "patch_location": location, "patch_destination": destination,
                  "original_sha256": _sha(b"original"), "verified": False}
        _write(Path(workdir) / "patch-stage.json", json.dumps(marker))
        _write(Path(workdir) / "patch-format", format_text + "\n")
        _write(Path(workdir) / "patch-location", location.removeprefix("0x") + "\n")
        _write(Path(workdir) / "destinations", destination.removeprefix("0x") + "\n")
        _write(Path(workdir) / "patch-destination", destination.removeprefix("0x") + "\n")
        if format_text.endswith("CWE-805"):
            _write(Path(workdir) / "trace/malloc.calls", "0 400100\n1 400200\n")
            _write(Path(workdir) / "trace/malloc.returns", "400110\n")
            _write(Path(workdir) / "trace/private-trial-diagnostic", "not a dependency")
        if not built:
            _write(Path(workdir) / "stack-size", "64\n")
        if built:
            for suffix in ("patched", "patched.json", "brpatched", "brpatched.json"):
                _write(Path(workdir) / f"fixture.{suffix}", f"{suffix}:{destination}")
        return marker

    def setup(self, workdir, timeout, environment):
        self.setups.append(Path(workdir).name)
        destination = (Path(workdir) / "patch-destination").read_text().strip()
        total = 0 if destination in self.setup_rejected else 1
        _write(Path(workdir) / "binradar.env",
               f'TOTAL_PATCHES="{total}"\nFILTER_TOTAL_PATCHES="{total}"\n')
        _write(Path(workdir) / "filter.sbsv",
               f"[filter] [res] [id 1] [pass {'true' if total else 'false'}] "
               f"[new-id {1 if total else -1}] (fixture)\n")
        return {"TOTAL_PATCHES": str(total), "FILTER_TOTAL_PATCHES": str(total)}

    def observe(self, workdir, settings, input_path, *, artifact, directory, patch_id=0):
        assert Path(workdir).is_dir() and self.tmp_path in Path(directory).parents
        original = artifact.endswith(".orig")
        if self.mode == "unavailable":
            raise RuntimeError("observation-unavailable: fixture")
        content = Path(input_path).read_bytes()
        location = settings["PATCH_LOC"]
        self.observations.append((artifact, location, content))
        crash = content in (b"malicious", b"unrelated")
        fault = 0x401c30 if content == b"malicious" else 0x402bad if crash else 0
        hits = 0 if (location, content) in self.nonhits else 1
        rejected = (self.mode == "reject"
                    or (self.mode == "accept-second" and workdir.name.endswith("0x401a1f"))
                    or (location, (Path(workdir) / "patch-destination").read_text().strip())
                    in self.reject_actions)
        if original and self.mode == "drift" and crash:
            fault = 0x402bad
        if not original:
            if content == b"malicious" and not rejected:
                crash, fault = False, 0
            if content == b"unrelated" and self.mode == "erase-other":
                crash, fault = False, 0
            if content == b"normal" and self.mode in ("unknown-normal", "new-crash"):
                crash, fault = True, 0 if self.mode == "unknown-normal" else 0x402bad
        outcome = "crash" if crash else "normal"
        if not original and self.mode == "trap":
            outcome = "trap"
        serialized = _case(0, "unused", content,
                           exit_info="crash" if crash else "ok", fault=f"{fault:x}",
                           location=location.removeprefix("0x"), hits=hits)
        probe = "[version 4]" + serialized.split("[version 4]", 1)[1].rsplit(" [time", 1)[0]
        return {"artifact_sha256": ("b" * 64 if not original and self.mode == "wrong-artifact"
                                    else _sha((Path(workdir) / artifact).read_bytes())),
                "input_sha256": ("c" * 64 if not original and self.mode == "wrong-input"
                                 else _sha(content)),
                "outcome": {"outcome": outcome, "fault_addr": fault,
                            "fault_valid": crash and fault != 0},
                "patch_hits": hits, "probe": probe,
                "branches": None if original else [1] if content == b"malicious" else [0]}


@pytest.fixture
def single_subject(subject):
    subject_dir, source, run = subject
    # Move the prepared site to the reported fault so a nonallocator SIGSEGV
    # selects Single CWE-823.
    _write(source / "patch-candidates", "401c30 401a1f 401b59\n")
    _write(source / "patch-location", "401c30\n")
    _write(source / "trace/crash.address", "401c30\n")
    _write(source / "generate-concrete.env",
           'BINARY="fixture"\nTEST_CMD="@@ "\nPATCH_LOC="0x401c30"\n'
           'POC_INPUT="input/poc/poc"\nPOC_DIR="input/poc"\n')
    text = (run / "minimizer.sbsv").read_text().replace("patch-loc 401a82", "patch-loc 401c30")
    _write(run / "minimizer.sbsv", text)
    _identity(run, location="0x401c30")
    return subject_dir, source, run


def _select_args(subject_dir, source, run, output):
    return selector.parse_args(["--subject", str(subject_dir), "--workdir", str(source),
                                "--concrete-run", str(run), "--output", str(output)])


def _install(monkeypatch, backend):
    monkeypatch.setattr(selector, "_stage", backend.stage)
    monkeypatch.setattr(selector, "_setup", backend.setup)
    monkeypatch.setattr(selector, "observe", backend.observe)


def test_selector_publishes_accepted_single_and_authenticates_it(
        tmp_path, monkeypatch, single_subject):
    subject_dir, source, run = single_subject
    before = {str(path.relative_to(source)): path.read_bytes()
              for path in source.rglob("*") if path.is_file()}
    output = tmp_path / "patch"
    backend = FakeBackend(tmp_path)
    _install(monkeypatch, backend)
    assert selector.select(_select_args(subject_dir, source, run, output)) == 0
    saved = selector.load_patch_selection(output)
    assert saved["selection"] == "single"
    assert saved["patch_format"] == "Single CWE-823"
    assert saved["patch_location"] == "0x401c30"
    assert saved["patch_destination"] == "0x401a1f"
    assert saved["trials"][0]["status"] == "accepted"
    assert saved["publication"]["artifact"]["path"] == "fixture.brpatched"
    assert (output / "evaluation.json").is_file()
    assert (output / "fixture.brpatched").read_text() == "brpatched:0x401a1f"
    # Source preparation and the produced corpus stay byte-identical.
    after = {str(path.relative_to(source)): path.read_bytes()
             for path in source.rglob("*") if path.is_file()}
    assert after == before
    assert not (tmp_path / "patch" / "trials" / "000-cwe-823-0x401a1f" / "trials").exists()


def test_selector_tries_next_destination_after_setup_rejection(
        tmp_path, monkeypatch, single_subject):
    subject_dir, source, run = single_subject
    output = tmp_path / "patch"
    backend = FakeBackend(tmp_path, setup_rejected={"401a1f"})
    _install(monkeypatch, backend)
    assert selector.select(_select_args(subject_dir, source, run, output)) == 0
    saved = selector.load_patch_selection(output)
    assert saved["patch_destination"] == "0x401b59"
    assert [row["status"] for row in saved["trials"]] == ["rejected", "accepted"]
    assert saved["trials"][0]["reason"] == "setup_rejected"


def test_selector_falls_back_to_clean_erm_after_evidence_rejection(
        tmp_path, monkeypatch, single_subject):
    subject_dir, source, run = single_subject
    output = tmp_path / "patch"
    backend = FakeBackend(tmp_path, mode="reject")
    _install(monkeypatch, backend)
    assert selector.select(_select_args(subject_dir, source, run, output)) == 0
    saved = selector.load_patch_selection(output)
    assert saved["selection"] == "erm"
    assert saved["patch_format"] == "ERM generic"
    assert "publication" not in saved
    assert [row["status"] for row in saved["trials"]] == ["rejected", "rejected"]
    assert {row["reason"] for row in saved["trials"]} == {"target_crash"}
    assert (output / "patch-stage.json").read_text().count('"prepared"') == 1
    assert not (output / "fixture.brpatched").exists()


def test_selector_never_trials_or_reobserves_actionless_scout_sites(
        tmp_path, monkeypatch, single_subject):
    subject_dir, source, run = single_subject
    _write(source / "poc-exit-code", "134\n")
    _write(source / "patch-candidates", "40118e\n401c30 401a1f 401b59\n")
    backend = FakeBackend(tmp_path, mode="reject")
    _install(monkeypatch, backend)
    output = tmp_path / "patch"
    selector.select(_select_args(subject_dir, source, run, output))
    saved = selector.load_patch_selection(output)
    assert saved["selection"] == "erm"
    assert [(stage[1], stage[2], stage[3]) for stage in backend.stages] == [
        ("Single CWE-617", "0x401c30", "0x401a1f"),
        ("Single CWE-617", "0x401c30", "0x401b59"),
        ("ERM generic", "0x401c30", "0x401a1f"),
    ]
    assert len(saved["trials"]) == 2
    assert {site for artifact, site, _ in backend.observations
            if artifact.endswith(".orig")} == {"0x401c30"}
    assert (source / "patch-candidates").read_text() == "40118e\n401c30 401a1f 401b59\n"


def test_selector_reports_unavailable_evidence_without_publication(
        tmp_path, monkeypatch, single_subject):
    subject_dir, source, run = single_subject
    output = tmp_path / "patch"
    backend = FakeBackend(tmp_path, mode="unavailable")
    _install(monkeypatch, backend)
    with pytest.raises(SelectionError, match="observation unavailable"):
        selector.select(_select_args(subject_dir, source, run, output))
    assert not output.exists()
    assert not list(tmp_path.glob(".patch.*"))


def test_selector_refuses_existing_output_and_source_overlap(
        tmp_path, monkeypatch, single_subject):
    subject_dir, source, run = single_subject
    output = tmp_path / "patch"
    output.mkdir()
    backend = FakeBackend(tmp_path)
    _install(monkeypatch, backend)
    with pytest.raises(SelectionError, match="output already exists"):
        selector.select(_select_args(subject_dir, source, run, output))
    with pytest.raises(SelectionError, match="outside the immutable source"):
        selector.select(_select_args(subject_dir, source, run, source / "nested"))
    assert backend.stages == [] and backend.setups == []


@pytest.mark.parametrize("change", [
    lambda text: text.replace("[version 4]", "[version 3]", 1),
    lambda text: text.replace("[patch-hit 1]", "[patch-hit not-an-int]", 1),
    lambda text: text.replace("[input-sha256 ", "[missing-sha256 ", 1),
    lambda text: text.replace("[concrete-fault-valid true]", "[concrete-fault-valid false]", 1),
    lambda text: text.replace("[fault-addr 401c30]", "[fault-addr 0]", 1),
    lambda text: text.replace("[raw-fault-addr 401c30]", "[raw-fault-addr 0]", 1),
    lambda text: text.replace("[concrete-fault-source native]", "[concrete-fault-source unavailable]", 1),
    lambda text: text.replace("[minimizer] [done]\n", "[minimizer] [done]\n[testcase] [original-result] garbage\n"),
    lambda text: text.rstrip("\n"),
])
def test_malformed_original_rows_never_drop_repair_obligations(subject, change):
    _, _, run = subject
    _write(run / "minimizer.sbsv", change((run / "minimizer.sbsv").read_text()))
    with pytest.raises(SelectionError):
        selector._concrete_rows(run, 0x401a82, check_inputs=True)


@pytest.mark.parametrize("mode,error", [("unknown-normal", "unknown crash fault"),
                                         ("trap", "observation unavailable"),
                                         ("drift", "original fault drifted"),
                                         ("wrong-artifact", "observation identity changed"),
                                         ("wrong-input", "observation identity changed")])
def test_unknown_candidate_and_original_fault_drift_are_operational_errors(
        tmp_path, monkeypatch, single_subject, mode, error):
    subject_dir, source, run = single_subject
    output = tmp_path / "patch"
    backend = FakeBackend(tmp_path, mode=mode)
    _install(monkeypatch, backend)
    with pytest.raises(SelectionError, match=error):
        selector.select(_select_args(subject_dir, source, run, output))
    assert not output.exists()
    assert not list(tmp_path.glob(".patch.*"))


def test_selector_tries_captured_action_missing_from_initial_destination_list(
        tmp_path, monkeypatch, single_subject):
    subject_dir, source, run = single_subject
    _write(source / "patch-candidates", "401c30 401a1f 401b59 402100\n")
    backend = FakeBackend(tmp_path, reject_actions={("0x401c30", "401a1f"),
                                                  ("0x401c30", "401b59")})
    _install(monkeypatch, backend)
    output = tmp_path / "patch"
    selector.select(_select_args(subject_dir, source, run, output))
    saved = selector.load_patch_selection(output)
    assert saved["selection"] == "single" and saved["patch_destination"] == "0x402100"
    assert [stage[3] for stage in backend.stages] == ["0x401a1f", "0x401b59", "0x402100"]


def test_normal_input_new_known_crash_rejects_single(tmp_path, monkeypatch, single_subject):
    subject_dir, source, run = single_subject
    output = tmp_path / "patch"
    backend = FakeBackend(tmp_path, mode="new-crash")
    _install(monkeypatch, backend)
    selector.select(_select_args(subject_dir, source, run, output))
    saved = selector.load_patch_selection(output)
    assert saved["selection"] == "erm"
    assert [trial["reason"] for trial in saved["trials"]] == ["other_crash", "other_crash"]


@pytest.mark.parametrize("mode,expected", [("accept", "single"), ("erase-other", "erm")])
def test_unrelated_crash_must_stay_the_same_crash(
        tmp_path, monkeypatch, single_subject, mode, expected):
    subject_dir, source, run = single_subject
    _write(run / "minimized/2_other", b"unrelated")
    text = (run / "minimizer.sbsv").read_text().replace(
        "[minimizer] [done]", _case(2, "2_other", b"unrelated", fault="402bad",
                                     location="401c30") + "\n[minimizer] [done]")
    _write(run / "minimizer.sbsv", text)
    output = tmp_path / "patch"
    backend = FakeBackend(tmp_path, mode=mode)
    _install(monkeypatch, backend)
    selector.select(_select_args(subject_dir, source, run, output))
    saved = selector.load_patch_selection(output)
    assert saved["selection"] == expected
    if expected == "single":
        evaluation = json.loads((output / "evaluation.json").read_text())
        other = next(row for row in evaluation["observations"] if row["id"] == 2)
        assert other["status"] == "preserved" and other["same_other_crash"] is True
        assert evaluation["summary"] == {"repaired": 1, "preserved": 2}
    else:
        assert {trial["reason"] for trial in saved["trials"]} == {"unrelated_crash_changed"}


@pytest.mark.parametrize("exit_code,allocator,family", [
    (134, False, "Single CWE-617"), (136, False, "Single CWE-369"),
    (139, False, "Single CWE-823"), (139, True, "Single CWE-805"),
])
def test_selector_traverses_captured_sites_and_publishes_fresh_original_hits(
        tmp_path, monkeypatch, subject, exit_code, allocator, family):
    subject_dir, source, run = subject
    _write(source / "poc-exit-code", str(exit_code))
    _write(source / "patch-candidates", "401a82 401a1f 401b59\n401c30 402000 402100\n")
    if allocator:
        _write(source / "trace/qasan.log", "#0 0x400100 in __libqasan_malloc\n")
    before = {str(path.relative_to(source)): path.read_bytes()
              for path in source.rglob("*") if path.is_file()}
    backend = FakeBackend(tmp_path,
                          reject_actions={("0x401a82", "401a1f"), ("0x401a82", "401b59"),
                                          ("0x401c30", "402000")},
                          nonhits={("0x401c30", b"normal")})
    _install(monkeypatch, backend)
    output = tmp_path / "patch"
    selector.select(_select_args(subject_dir, source, run, output))
    saved = selector.load_patch_selection(output)
    assert saved["selection"] == "single" and saved["patch_format"] == family
    assert saved["patch_location"] == "0x401c30" and saved["patch_destination"] == "0x402100"
    attempted = [(stage[2], stage[3]) for stage in backend.stages]
    expected = [("0x401c30", "0x402000"), ("0x401c30", "0x402100")]
    if exit_code == 134:
        expected = [("0x401a82", "0x401a1f"), ("0x401a82", "0x401b59"), *expected]
    assert attempted == expected
    assert saved["source_concrete"]["path"] == str(run)
    assert saved["source_concrete"]["location"] == "0x401a82"
    assert saved["concrete_run"] == str(output / "concrete")
    assert saved["concrete"]["cases"] == 1
    source_identity = json.loads((run / "original-identity.json").read_text())
    selected_identity = json.loads((output / "concrete/original-identity.json").read_text())
    assert source_identity["kind"] == "original-only-minimizer"
    assert source_identity["patch_location"] == "0x401a82"
    assert selected_identity["kind"] == "selected-site-original-reobservation"
    assert selected_identity["patch_location"] == "0x401c30"
    assert saved["concrete"]["identity"]["sha256"] != saved["source_concrete"]["identity"]["sha256"]
    new_rows, terminal = selector._concrete_rows(output / "concrete", 0x401c30, check_inputs=True)
    assert terminal == "done" and [row["id"] for row in new_rows] == [0]
    assert new_rows[0]["original"]["patch-loc"] == 0x401c30
    assert new_rows[0]["path"].read_bytes() == b"malicious"
    proof = json.loads((output / "evaluation.json").read_text())
    assert [(row["id"], row["patch_hits"]) for row in proof["originals"]] == [(0, 1), (1, 0)]
    assert [row["id"] for row in proof["observations"]] == [0, 1]
    assert selector._environments(output)["generate-concrete.env"]["PATCH_LOC"] == "0x401c30"
    assert {(site, content) for artifact, site, content in backend.observations
            if artifact.endswith(".orig")} == {
                (site, content) for site in ("0x401a82", "0x401c30")
                for content in (b"malicious", b"normal")}
    assert {str(path.relative_to(source)): path.read_bytes()
            for path in source.rglob("*") if path.is_file()} == before
    if allocator:
        from binradar.binradar_taosc_predicates import parse_allocator_trace
        assert parse_allocator_trace(output / "trace").kind == "malloc"
        assert "trace/malloc.calls" in saved["artifacts"]
        assert "trace/malloc.returns" in saved["artifacts"]
        assert not (output / "trace/private-trial-diagnostic").exists()
    # Renaming a completed publication must not keep a staging/old output path.
    renamed = tmp_path / "renamed"
    output.rename(renamed)
    assert selector.load_patch_selection(renamed)["concrete_run"] == str(renamed / "concrete")
    # Re-observation never removes the independent source-corpus binding.
    _write(run / "minimized/1_second", b"changed source nonhit")
    with pytest.raises(SelectionError, match="identity changed"):
        selector.load_patch_selection(renamed)


def test_single805_publishes_and_authenticates_allocator_pair(
        tmp_path, monkeypatch, single_subject):
    subject_dir, source, run = single_subject
    _write(source / "trace/qasan.log", "#0 0x400100 in __libqasan_malloc\n")
    backend = FakeBackend(tmp_path)
    _install(monkeypatch, backend)
    output = tmp_path / "patch"
    selector.select(_select_args(subject_dir, source, run, output))
    saved = selector.load_patch_selection(output)
    from binradar.binradar_taosc_predicates import parse_allocator_trace
    assert parse_allocator_trace(output / "trace").calls == [(0, "400100"), (1, "400200")]
    assert not (source / "trace/malloc.calls").exists()
    _write(output / "trace/malloc.returns", "400120\n")
    with pytest.raises(SelectionError, match="checksum mismatch"):
        selector.load_patch_selection(output)
    _write(output / "trace/malloc.returns", "400110\n")
    del saved["artifacts"]["trace/malloc.calls"]
    _write(output / "patch-selection.json", json.dumps(saved))
    with pytest.raises(SelectionError, match="allocator dependency"):
        selector.load_patch_selection(output)


@pytest.mark.parametrize("tamper", ["drop-source", "source-original", "source-log"])
def test_current_selection_keeps_source_preparation_and_corpus_bound(
        tmp_path, monkeypatch, single_subject, tamper):
    subject_dir, source, run = single_subject
    backend = FakeBackend(tmp_path)
    _install(monkeypatch, backend)
    output = tmp_path / "patch"
    selector.select(_select_args(subject_dir, source, run, output))
    saved = selector.load_patch_selection(output)
    if tamper == "drop-source":
        del saved["source_concrete"]
        _write(output / "patch-selection.json", json.dumps(saved))
    elif tamper == "source-original":
        _write(source / "fixture.orig", b"new source original")
    else:
        _write(source / "trace/qasan.log", "different crash log")
    with pytest.raises(SelectionError, match="source concrete identity|checksum mismatch"):
        selector.load_patch_selection(output)


def test_same_site_missing_original_hit_remains_drift(tmp_path, monkeypatch, single_subject):
    subject_dir, source, run = single_subject
    backend = FakeBackend(tmp_path, nonhits={("0x401c30", b"normal")})
    _install(monkeypatch, backend)
    output = tmp_path / "patch"
    with pytest.raises(SelectionError, match="no longer reaches"):
        selector.select(_select_args(subject_dir, source, run, output))
    assert not output.exists()


@pytest.mark.parametrize("tamper", ["drop-nonhit", "relabel-hit", "wrong-original-probe"])
def test_fresh_site_authentication_rejects_relabelled_or_incomplete_proof(
        tmp_path, monkeypatch, subject, tamper):
    subject_dir, source, run = subject
    _write(source / "patch-candidates", "401a82 401a1f 401b59\n401c30 402000\n")
    backend = FakeBackend(tmp_path, nonhits={("0x401c30", b"normal")})
    _install(monkeypatch, backend)
    output = tmp_path / "patch"
    selector.select(_select_args(subject_dir, source, run, output))
    saved = selector.load_patch_selection(output)
    if tamper == "relabel-hit":
        manifest = output / "concrete/minimizer.sbsv"
        _write(manifest, manifest.read_text().replace("[patch-hit 1]", "[patch-hit 2]"))
        saved["concrete"]["minimizer_sha256"] = _sha(manifest.read_bytes())
        saved["artifacts"]["concrete/minimizer.sbsv"] = selector._reference(output, manifest)
    else:
        path = output / "evaluation.json"
        proof = json.loads(path.read_text())
        if tamper == "drop-nonhit":
            proof["originals"].pop()
            proof["observations"].pop()
        else:
            proof["originals"][0]["probe"] = proof["originals"][0]["probe"].replace(
                "[patch-loc 401c30]", "[patch-loc 401a82]")
        _write(path, json.dumps(proof))
        saved["evaluation"] = selector._reference(output, path)
        saved["artifacts"]["evaluation.json"] = saved["evaluation"]
    _write(output / "patch-selection.json", json.dumps(saved))
    with pytest.raises(SelectionError, match="selected-site|fresh original observation"):
        selector.load_patch_selection(output)


def test_source_evidence_change_during_selection_publishes_nothing(
        tmp_path, monkeypatch, single_subject):
    subject_dir, source, run = single_subject
    backend = FakeBackend(tmp_path)
    _install(monkeypatch, backend)
    original_observe = backend.observe

    def change_source(*args, **kwargs):
        result = original_observe(*args, **kwargs)
        if (kwargs["artifact"].endswith(".brpatched")
                and result["input_sha256"] == _sha(b"malicious")):
            path = run / "minimizer.sbsv"
            _write(path, path.read_text().replace("[minimizer] [done]",
                                                "[minimizer] [stopped] [reason wall-time-reached]"))
        return result

    monkeypatch.setattr(selector, "observe", change_source)
    output = tmp_path / "patch"
    with pytest.raises(SelectionError, match="source concrete evidence changed"):
        selector.select(_select_args(subject_dir, source, run, output))
    assert not output.exists()



@pytest.mark.parametrize("fixture_name", ["subject", "single_subject"])
@pytest.mark.parametrize("normal_only", [False, True])
@pytest.mark.parametrize("damage", ["missing", "original", "binary", "command", "poc", "poc-path", "site"])
def test_all_selection_paths_require_authentic_producer_identity_before_work(
        tmp_path, monkeypatch, request, fixture_name, normal_only, damage):
    subject_dir, source, run = request.getfixturevalue(fixture_name)
    if normal_only:
        text = (run / "minimizer.sbsv").read_text()
        _write(run / "minimizer.sbsv", "\n".join(
            line for line in text.splitlines() if "[id 0]" not in line) + "\n")
    identity = run / "original-identity.json"
    if damage == "missing":
        identity.unlink()
    else:
        value = json.loads(identity.read_text())
        key, changed = {"original": ("original_sha256", _sha(b"another original")),
                        "binary": ("binary", "another"),
                        "command": ("invocation", ["--different", "@@"]),
                        "poc": ("poc", {"path": "input/poc/poc", "sha256": _sha(b"another poc")}),
                        "poc-path": ("poc", {"path": "input/poc/other", "sha256": _sha(b"malicious")}),
                        "site": ("patch_location", "0x402000")}[damage]
        value[key] = changed
        _write(identity, json.dumps(value))
    backend = FakeBackend(tmp_path)
    _install(monkeypatch, backend)
    output = tmp_path / "not-created" / "patch"
    with pytest.raises(SelectionError, match="producer original"):
        selector.select(_select_args(subject_dir, source, run, output))
    assert not output.parent.exists()
    assert not backend.observations and not backend.stages and not backend.setups


@pytest.mark.parametrize("damage", ["config-command", "args-command", "generation-command", "config-poc", "generation-poc"])
def test_selector_rejects_inconsistent_effective_invocation_before_work(
        tmp_path, monkeypatch, subject, damage):
    subject_dir, source, run = subject
    if damage.endswith("command"):
        path = (subject_dir / "config.env" if damage == "config-command" else
                source / "args" if damage == "args-command" else source / "generate-concrete.env")
        _write(path, path.read_text().replace("@@", "--different @@"))
    else:
        _write(source / "input/poc/other", b"malicious")
        path = subject_dir / "config.env" if damage == "config-poc" else source / "generate-concrete.env"
        _write(path, path.read_text().replace("input/poc/poc", "input/poc/other"))
    backend = FakeBackend(tmp_path)
    _install(monkeypatch, backend)
    output = tmp_path / "not-created" / "patch"
    with pytest.raises(SelectionError, match="invocation|PoC"):
        selector.select(_select_args(subject_dir, source, run, output))
    assert not output.parent.exists()
    assert not backend.observations and not backend.stages and not backend.setups


def test_selector_compares_parsed_invocations_not_whitespace_or_quoting(
        tmp_path, monkeypatch, subject):
    subject_dir, source, run = subject
    _write(source / "args", 'fixture --flag "two words" @@\n')
    path = source / "generate-concrete.env"
    _write(path, path.read_text().replace('TEST_CMD="@@ "', 'TEST_CMD="--flag \'two words\' @@"'))
    path = subject_dir / "config.env"
    _write(path, path.read_text().replace("TEST_CMD=@@", 'TEST_CMD=" --flag  two\\ words   @@ "'))
    _identity(run, invocation=["--flag", "two words", "@@"])
    backend = FakeBackend(tmp_path)
    _install(monkeypatch, backend)
    output = tmp_path / "patch"
    selector.select(_select_args(subject_dir, source, run, output))
    assert selector.load_patch_selection(output)["selection"] == "erm"
    assert len(backend.observations) == 2 and not backend.setups


@pytest.mark.parametrize("mode,error", [("drift", "original fault drifted"),
                                         ("unavailable", "observation unavailable")])
def test_no_single_path_still_requires_fresh_original_replay(
        tmp_path, monkeypatch, subject, mode, error):
    subject_dir, source, run = subject
    backend = FakeBackend(tmp_path, mode=mode)
    _install(monkeypatch, backend)
    output = tmp_path / "patch"
    with pytest.raises(SelectionError, match=error):
        selector.select(_select_args(subject_dir, source, run, output))
    assert not output.exists() and not backend.stages


@pytest.mark.parametrize("change", ["identity", "config"])
def test_no_single_path_rechecks_producer_and_configuration_before_publication(
        tmp_path, monkeypatch, subject, change):
    subject_dir, source, run = subject
    backend = FakeBackend(tmp_path)
    _install(monkeypatch, backend)
    def mutate_after_stage(*args, **kwargs):
        marker = backend.stage(*args, **kwargs)
        path = run / "original-identity.json" if change == "identity" else subject_dir / "config.env"
        _write(path, path.read_text() + (" " if change == "identity" else "# changed\n"))
        return marker
    monkeypatch.setattr(selector, "_stage", mutate_after_stage)
    output = tmp_path / "patch"
    with pytest.raises(SelectionError, match="source concrete evidence changed|configuration changed"):
        selector.select(_select_args(subject_dir, source, run, output))
    assert not output.exists()


@pytest.mark.parametrize("change", ["identity", "config"])
def test_saved_selection_rejects_changed_producer_identity_or_configuration(
        tmp_path, monkeypatch, subject, change):
    subject_dir, source, run = subject
    backend = FakeBackend(tmp_path)
    _install(monkeypatch, backend)
    output = tmp_path / "patch"
    selector.select(_select_args(subject_dir, source, run, output))
    saved = selector.load_patch_selection(output)
    assert saved["source_concrete"]["identity"] == selector._reference(run, run / "original-identity.json")
    path = run / "original-identity.json" if change == "identity" else subject_dir / "config.env"
    _write(path, path.read_text() + (" " if change == "identity" else "# changed\n"))
    with pytest.raises(SelectionError, match="checksum mismatch|configuration identity changed"):
        selector.load_patch_selection(output)


def test_atomic_publication_never_replaces_concurrent_empty_directory(tmp_path):
    staging, output = tmp_path / "staging", tmp_path / "output"
    staging.mkdir()
    _write(staging / "owned", b"selected")
    output.mkdir()
    with pytest.raises(SelectionError, match="cannot publish fresh output"):
        selector._publish_directory(staging, output)
    assert list(output.iterdir()) == [] and (staging / "owned").read_bytes() == b"selected"
