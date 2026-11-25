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


def _case(case_id: int, filename: str, data: bytes, *, exit_info="crash",
          fault="401c30") -> str:
    return (f"[testcase] [original-result] [id {case_id}] [file {filename}] "
            f"[input-sha256 {_sha(data)}] [version 4] [exit {exit_info}] "
            f"[patch-loc 401a82] [func-entry 4018c0] [patch-hit 1] [func-hit 1] "
            f"[fault-addr {fault if exit_info == 'crash' else 0}] "
            f"[tracer-fault-valid false] [tracer-fault-source unavailable] "
            f"[tracer-fault-addr 0] [tracer-fault-image none] [tracer-fault-image-offset 0] "
            f"[memcheck-policy unavailable] [patch-func-candidates [4018c0:1]] "
            f"[stacktrace []] [concrete-oracle qasan-main-v2] "
            f"[concrete-fault-valid {'true' if exit_info == 'crash' else 'false'}] "
            f"[raw-fault-addr 0] [concrete-fault-source "
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
           'BINARY="fixture"\nTEST_CMD="@@ "\nPATCH_LOC="0x401a82"\n')
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
    return subject, source, run


def test_metadata_accepts_common_preparation_without_stage_marker(subject):
    _, source, _ = subject
    metadata = selector._metadata(source)
    assert metadata["binary"] == "fixture"
    assert metadata["location_text"] == "0x401a82"
    assert metadata["destination"] == 0x401a1f
    assert metadata["destinations"] == [0x401a1f, 0x401b59]
    assert metadata["candidates"][0x401a82] == [0x401a1f, 0x401b59]


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
    for name in ("fixture.orig", "fixture.brpatched", "fixture.brpatched.json"):
        _write(root / name, name.encode())
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
    rows, terminal = selector._concrete_rows(run, 0x401a82, check_inputs=True)
    value["concrete"].update(minimizer_sha256=_sha((run / "minimizer.sbsv").read_bytes()),
                             cases=len(rows), cases_sha256=selector._case_digest(rows, terminal))


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

    def __init__(self, tmp_path, *, mode="accept", setup_rejected=()):
        self.tmp_path = tmp_path
        self.mode = mode
        self.setup_rejected = set(setup_rejected)
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
        crash = content == b"malicious"
        if original:
            return {"outcome": {"outcome": "crash" if crash else "normal",
                                "fault_addr": 0x401c30 if crash else 0},
                    "patch_hits": 1, "normal_signature": None if crash else
                    {"exit_code": 0, "stdout_sha256": "a" * 64, "stdout_size": 0},
                    "branches": None, "target_crash": crash}
        rejected = self.mode == "reject" or (self.mode == "accept-second"
                                             and workdir.name.endswith("0x401a1f"))
        if crash and (self.mode == "reject" or rejected):
            return {"outcome": {"outcome": "crash", "fault_addr": 0x401c30},
                    "patch_hits": 1, "normal_signature": None, "branches": [1]}
        return {"outcome": {"outcome": "normal", "fault_addr": 0},
                "patch_hits": 0 if not crash else 1,
                "normal_signature": {"exit_code": 0, "stdout_sha256": "a" * 64,
                                     "stdout_size": 0},
                "branches": [1] if crash else [0]}


@pytest.fixture
def single_subject(subject):
    subject_dir, source, run = subject
    # Move the prepared site to the reported fault so a nonallocator SIGSEGV
    # selects Single CWE-823.
    _write(source / "patch-candidates", "401c30 401a1f 401b59\n")
    _write(source / "patch-location", "401c30\n")
    _write(source / "trace/crash.address", "401c30\n")
    _write(source / "generate-concrete.env",
           'BINARY="fixture"\nTEST_CMD="@@ "\nPATCH_LOC="0x401c30"\n')
    text = (run / "minimizer.sbsv").read_text().replace("patch-loc 401a82", "patch-loc 401c30")
    _write(run / "minimizer.sbsv", text)
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
