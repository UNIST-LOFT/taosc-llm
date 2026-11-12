"""Public runner options and real, immutable filesystem reservations."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import stat

import pytest

from taosc_llm.runner_options import allocate_run, output_base, parse_args


def test_defaults_capture_invocation_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    args = parse_args([])
    assert args.mode == "no-llm"
    assert args.cwd == args.subject == tmp_path
    assert args.workdir == tmp_path / "workdir-0.1.24"
    assert output_base(args) == args.workdir / "out"
    assert args.run_prefix == "taosc-llm-no-llm-out"
    assert args.run_id == "n"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert output_base(args) == tmp_path / "workdir-0.1.24/out"
    assert not args.workdir.exists()


def test_dataset_base_uses_captured_cwd_not_subject(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    args = parse_args(["--dataset", "frozen", "--subject", "subject"])
    assert args.dataset == tmp_path / "frozen"
    assert output_base(args) == tmp_path
    assert allocate_run(args) == tmp_path / "taosc-llm-no-llm-out-00000"


@pytest.mark.parametrize("mode,extras", [("manual", ["--predicate", "1"]), ("provider", ["--provider-env", "provider.env"])])
def test_mode_defaults_and_required_synthesis_options(tmp_path, monkeypatch, mode, extras):
    monkeypatch.chdir(tmp_path)
    args = parse_args(["--mode", mode, *extras])
    assert args.run_prefix == "taosc-llm-out"
    assert args.max_rounds == (4 if mode == "provider" else None)
    assert parse_args(["--mode", mode, "--stop-after", "warm"]).mode == mode
    if mode == "provider":
        assert args.provider_env == tmp_path / "provider.env"


def test_normalization_preserves_lexical_symlink_parents(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    args = parse_args([
        "--subject", "~/alias", "--workdir", "nested/../work", "--dataset", "alias/dataset",
        "--output", "alias/result", "--replay-socket", "alias/replay.sock", "--rea", "alias/rea",
    ])
    assert args.subject == alias
    assert args.workdir == alias / "work"
    assert args.dataset == alias / "dataset"
    assert args.output == alias / "result"
    assert args.replay_socket == alias / "replay.sock"
    assert args.rea == str(alias / "rea")
    selected = allocate_run(args)
    assert selected == alias / "result"
    assert (real / "result").is_dir()
    assert parse_args(["--rea", "rea"]).rea == "rea"


@pytest.mark.parametrize("argv", [
    ["--output", "result", "--run-prefix", "taosc-llm-no-llm-out"],
    ["--output", "result", "--run-id", "n"],
    ["--output", "result", "--run-id", "0"],
    ["--dataset", "data", "--concrete-run", "concrete"],
    ["--dataset", "data", "--binradar-run", "mutation"],
    ["--dataset", "data", "--concrete-only"],
    ["--dataset", "data", "--stop-after", "generation"],
    ["--dataset", "data", "--stop-after", "dataset"],
    ["--concrete-only", "--binradar-run", "mutation"],
    ["--replay-socket", "socket"],
    ["--concrete-run", "concrete", "--replay-socket", "socket"],
    ["--concrete-only", "--binradar-run", "mutation", "--replay-socket", "socket"],
    ["--mode", "manual"],
    ["--mode", "provider"],
    ["--predicate", "1"],
    ["--provider-env", "provider.env"],
    ["--pi-sdk-root", "sdk"],
    ["--max-rounds", "4"],
    ["--session-feedback"],
    ["--mode", "manual", "--predicate", "1", "--provider-env", "provider.env"],
    ["--mode", "provider", "--provider-env", "provider.env", "--predicate", "1"],
    ["--resume"],
    ["--resume", "--run-id", "n"],
    ["--resume", "--run-id", "0", "--concrete-run", "concrete"],
    ["--resume", "--run-id", "0", "--binradar-run", "mutation"],
    ["--resume", "--run-id", "0", "--concrete-only"],
    ["--run-id", "l"],
    ["--resume", "--run-id", "0", "--stop-after", "warm"],
    ["--resume", "--output", "result", "--mode", "manual", "--predicate", "1"],
    ["--resume", "--output", "result", "--mode", "provider", "--provider-env", "provider.env"],
    ["--timeout", "1"], ["--no-llm"], ["--skip-concrete"], ["--only-concrete"], ["--outdir", "out"],
    ["--sub", "subject"], ["--max-executions", "10000"],
    ["--binradar-representative-budget", "-1"],
    ["--binradar-representative-budget", "2147483648"],
    ["--binradar-representative-budget", "1", "--dataset", "data"],
    ["--binradar-representative-budget", "1", "--binradar-run", "mutation"],
    ["--binradar-representative-budget", "1", "--concrete-only"],
    ["--forkserver-child-timeout", "0"],
    ["--forkserver-child-timeout", "10", "--dataset", "data"],
    ["--forkserver-child-timeout", "10", "--concrete-only", "--concrete-run", "concrete"],
    ["--concrete-timeout", "-1"],
])
def test_invalid_combinations_do_not_create_output(tmp_path, monkeypatch, argv):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc:
        parse_args(argv)
    assert exc.value.code == 2
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("option", [
    "search-timeout", "max-evaluations", "max-atoms", "beam-width",
    "max-clauses", "max-factors", "operand-depth",
])
@pytest.mark.parametrize("mode", ["manual", "provider"])
def test_explicit_search_defaults_are_rejected_in_other_modes(option, mode):
    default = getattr(parse_args([]), option.replace("-", "_"))
    with pytest.raises(SystemExit) as exc:
        parse_args(["--mode", mode, "--stop-after", "warm", "--" + option, str(default)])
    assert exc.value.code == 2


@pytest.mark.parametrize("option,value", [
    ("run-prefix", ""), ("run-prefix", "."), ("run-prefix", ".."), ("run-prefix", "a/b"), ("run-prefix", "a\\b"),
    ("run-id", "-1"), ("run-id", "1.5"), ("run-id", "latest"), ("run-id", "١"),
    ("execution-workers", "0"), ("execution-workers", "33"),
    ("analysis-timeout", "0"), ("analysis-query-timeout", "-1"),
    ("analysis-timeout", "2147484"), ("analysis-query-timeout", "2147484"),
    ("generation-timeout", "0.5"), ("generation-timeout", "-1"), ("ready-timeout", "nan"), ("stage-timeout", "inf"),
    ("graceful-timeout", "0"), ("graceful-timeout", "-inf"), ("search-timeout", "0"),
    ("max-evaluations", "0"), ("max-atoms", "65537"),
    ("beam-width", "257"), ("max-clauses", "129"), ("max-factors", "129"), ("operand-depth", "5"),
])
def test_invalid_option_bounds(option, value):
    with pytest.raises(SystemExit) as exc:
        parse_args(["--" + option, value])
    assert exc.value.code == 2


@pytest.mark.parametrize("value", ["0", "17"])
def test_provider_round_bounds(value):
    with pytest.raises(SystemExit) as exc:
        parse_args(["--mode", "provider", "--provider-env", "provider.env", "--max-rounds", value])
    assert exc.value.code == 2


def test_inclusive_bounds_and_explicit_unlimited_timeouts():
    args = parse_args([
        "--execution-workers", "32", "--generation-timeout", "0", "--ready-timeout", "0", "--stage-timeout", "0",
        "--max-atoms", "65536", "--beam-width", "256", "--max-clauses", "128", "--max-factors", "128", "--operand-depth", "4",
    ])
    assert args.generation_timeout == args.ready_timeout == args.stage_timeout == 0
    assert args.max_atoms == 65536
    assert args.beam_width == 256
    assert args.max_clauses == args.max_factors == 128
    assert args.operand_depth == 4
    provider = parse_args(["--mode", "provider", "--provider-env", "env", "--max-rounds", "16", "--session-feedback"])
    assert provider.max_rounds == 16 and provider.session_feedback


@pytest.mark.parametrize("reuse", [["--binradar-run", "mutation"], ["--dataset", "dataset"]])
def test_replay_requires_explicit_external_reuse(reuse):
    assert parse_args([*reuse, "--replay-socket", "socket"]).replay_socket.is_absolute()


@pytest.mark.parametrize("argv", [
    ["--concrete-only", "--stop-after", "generation"],
    ["--concrete-only", "--concrete-run", "concrete", "--stop-after", "generation"],
    ["--concrete-run", "concrete", "--binradar-run", "mutation", "--stop-after", "dataset"],
    ["--dataset", "dataset", "--stop-after", "warm"],
    ["--resume", "--output", "result", "--dataset", "dataset"],
    ["--resume", "--output", "result", "--replay-socket", "socket"],
])
def test_valid_source_and_stage_selections(argv):
    args = parse_args(argv)
    for name in ("concrete_run", "binradar_run", "dataset"):
        path = getattr(args, name)
        assert path is None or path.is_absolute()


def _args(base, *extra):
    return parse_args(["--workdir", str(base), *extra])


def test_sequential_reservation_and_private_mode(tmp_path):
    args = _args(tmp_path)
    first = allocate_run(args)
    (first / "evidence").write_text("retain me")
    second = allocate_run(args)
    assert first.name == "taosc-llm-no-llm-out-00000"
    assert second.name == "taosc-llm-no-llm-out-00001"
    assert stat.S_IMODE(first.stat().st_mode) == 0o700
    assert stat.S_IMODE(second.stat().st_mode) == 0o700
    assert (first / "evidence").read_text() == "retain me"


def test_gaps_numeric_files_symlinks_and_rollover_are_reserved(tmp_path):
    base = tmp_path / "out"
    base.mkdir()
    (base / "custom-00003").mkdir()
    (base / "custom-99999").write_text("reserved")
    (base / "custom-100000").symlink_to(tmp_path / "missing")
    for name in ("unrelated-999999", "custom-not-a-number", "custom-999999.tmp", "custom--1"):
        (base / name).touch()
    path = allocate_run(_args(tmp_path, "--run-prefix", "custom"))
    assert path == base / "custom-100001"
    assert (base / "custom-99999").read_text() == "reserved"
    assert (base / "custom-100000").is_symlink()


def test_short_numeric_suffix_is_also_reserved(tmp_path):
    (tmp_path / "out").mkdir()
    (tmp_path / "out/custom-9").touch()
    assert allocate_run(_args(tmp_path, "--run-prefix", "custom")).name == "custom-00010"


def test_concurrent_allocators_reserve_distinct_real_directories(tmp_path):
    args = _args(tmp_path)
    with ThreadPoolExecutor(max_workers=12) as pool:
        paths = list(pool.map(lambda _: allocate_run(args), range(40)))
    assert len(set(paths)) == 40
    assert all(path.is_dir() for path in paths)
    assert {path.name for path in paths} == {f"taosc-llm-no-llm-out-{number:05d}" for number in range(40)}


@pytest.mark.parametrize("selection", ["exact", "number"])
def test_existing_results_are_immutable_and_resume_is_explicit(tmp_path, selection):
    flags = ["--output", str(tmp_path / "result")] if selection == "exact" else ["--run-id", "0007"]
    args = _args(tmp_path, *flags)
    path = allocate_run(args)
    evidence = path / "evidence"
    evidence.write_bytes(b"private result\x00")
    before = evidence.stat()
    with pytest.raises(FileExistsError):
        allocate_run(args)
    assert allocate_run(_args(tmp_path, *flags, "--resume")) == path
    after = evidence.stat()
    assert evidence.read_bytes() == b"private result\x00"
    assert (before.st_ino, before.st_mtime_ns, before.st_size) == (after.st_ino, after.st_mtime_ns, after.st_size)
    if selection == "number":
        assert path.name == "taosc-llm-no-llm-out-00007"


@pytest.mark.parametrize("resume", [False, True])
@pytest.mark.parametrize("kind", ["directory-link", "dangling-link", "file"])
def test_exact_existing_symlinks_and_files_are_never_admitted(tmp_path, resume, kind):
    path = tmp_path / "selected"
    target = tmp_path / "target"
    if kind == "directory-link":
        target.mkdir()
        (target / "evidence").write_text("untouched")
        path.symlink_to(target, target_is_directory=True)
    elif kind == "dangling-link":
        path.symlink_to(target)
    else:
        path.write_text("untouched")
    args = _args(tmp_path, "--output", str(path), *(["--resume"] if resume else []))
    with pytest.raises((FileExistsError, NotADirectoryError)):
        allocate_run(args)
    if kind == "directory-link":
        assert (target / "evidence").read_text() == "untouched"
    elif kind == "file":
        assert path.read_text() == "untouched"
    else:
        assert path.is_symlink() and not target.exists()


@pytest.mark.parametrize("selection", [["--run-id", "7"], ["--run-id", "l"], ["--output", "missing"]])
def test_resume_missing_run_never_creates_directories(tmp_path, monkeypatch, selection):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(FileNotFoundError):
        allocate_run(_args(tmp_path, *selection, "--resume"))
    assert list(tmp_path.iterdir()) == []


def test_latest_selects_largest_existing_directory_without_mutation(tmp_path):
    base = tmp_path / "out"
    base.mkdir()
    for number in (3, 10, 100):
        (base / f"custom-{number:05d}").mkdir()
    (base / "custom-99999").write_text("not a directory")
    (base / "custom-99998").symlink_to(base / "custom-00100", target_is_directory=True)
    before = {path.name for path in base.iterdir()}
    selected = allocate_run(_args(tmp_path, "--run-prefix", "custom", "--run-id", "l", "--resume"))
    assert selected == base / "custom-00100"
    assert {path.name for path in base.iterdir()} == before


def test_latest_with_no_real_numbered_directory_fails(tmp_path):
    base = tmp_path / "out"
    base.mkdir()
    (base / "custom-00001").touch()
    (base / "custom-00002").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(FileNotFoundError):
        allocate_run(_args(tmp_path, "--run-prefix", "custom", "--run-id", "l", "--resume"))


@pytest.mark.parametrize("selection", [[], ["--run-id", "1"], ["--output", "out/child"]])
def test_non_directory_parent_fails_without_retry_or_replacement(tmp_path, monkeypatch, selection):
    monkeypatch.chdir(tmp_path)
    parent = tmp_path / "out"
    parent.write_text("preserve parent")
    with pytest.raises(OSError):
        allocate_run(_args(tmp_path, *selection))
    assert parent.read_text() == "preserve parent"


@pytest.mark.parametrize("error", [PermissionError, FileExistsError])
def test_non_collision_mkdir_error_is_propagated(tmp_path, monkeypatch, error):
    args = _args(tmp_path)
    output_base(args).mkdir()
    original = Path.mkdir
    attempted = []

    def deny_reservation(path, *positional, **keywords):
        if path.parent == output_base(args):
            attempted.append(path)
            raise error("reservation denied")
        return original(path, *positional, **keywords)

    monkeypatch.setattr(Path, "mkdir", deny_reservation)
    with pytest.raises(error, match="reservation denied"):
        allocate_run(args)
    assert len(attempted) == 1
