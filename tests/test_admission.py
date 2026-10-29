"""Offline consumer tests: ownership, cancellation and crash never recycle quota."""

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest
from taosc_llm.admission import (
    AdmissionError,
    QuotaOwner,
    QuotaOwnerBusy,
    QuotaQuarantinedError,
    recover_reservations,
)
from taosc_llm.provider import ProviderConfig


def config(**kwargs):
    if kwargs.get("max_in_flight") == 0:
        kwargs.update(base_url="https://example.invalid/v1", model="offline-future-provider")
    return ProviderConfig(api_key="offline-test-secret", **kwargs)


def state(path):
    return json.loads((path / "reservations.json").read_text())["reservations"]


@pytest.mark.parametrize("cap,workers,expected", [(3, 7, 3), (3, 2, 2), (0, 2, 2)])
def test_overlapping_workers_never_exceed_capacity(tmp_path, cap, workers, expected):
    async def scenario():
        active = 0
        peak = 0
        reached = asyncio.Event()
        release = asyncio.Event()
        with QuotaOwner(config(max_in_flight=cap, workers=workers), tmp_path) as owner:
            async def operation():
                nonlocal active, peak
                async with owner.reserve() as reservation:
                    assert state(tmp_path)[reservation.identifier] == "uncertain"
                    active += 1
                    peak = max(peak, active)
                    if active == expected:
                        reached.set()
                    await release.wait()
                    active -= 1
                    reservation.settle()
            tasks = [asyncio.create_task(operation()) for _ in range(9)]
            await asyncio.wait_for(reached.wait(), 2)
            # All admitted tasks remain held while the rest queue.
            assert len(state(tmp_path)) == expected
            assert active == expected
            release.set()
            await asyncio.wait_for(asyncio.gather(*tasks), 2)
            assert state(tmp_path) == {}
        assert peak == expected
    asyncio.run(scenario())


def test_settlement_releases_and_uncertain_exit_quarantines(tmp_path):
    async def scenario():
        with QuotaOwner(config(max_in_flight=1), tmp_path) as owner:
            async with owner.reserve() as first:
                first.settle()
            assert state(tmp_path) == {}
            async with owner.reserve() as uncertain:
                identifier = uncertain.identifier
            assert state(tmp_path) == {identifier: "quarantined"}
            with pytest.raises(QuotaQuarantinedError):
                async with owner.reserve():
                    pytest.fail("quarantined capacity reused")
            with pytest.raises(AdmissionError, match="already closed"):
                uncertain.settle()
        return identifier
    identifier = asyncio.run(scenario())
    with pytest.raises(QuotaQuarantinedError):
        with QuotaOwner(config(), tmp_path):
            pytest.fail("unresolved state silently reset")
    with pytest.raises(AdmissionError, match="confirmation"):
        recover_reservations(state_dir=tmp_path, confirm_provider_settled=False)
    assert state(tmp_path) == {identifier: "quarantined"}
    assert recover_reservations(state_dir=tmp_path, confirm_provider_settled=True) == [identifier]
    with QuotaOwner(config(), tmp_path):
        pass


def test_cancellation_quarantines_and_wakes_waiting_work(tmp_path):
    async def scenario():
        entered = asyncio.Event()
        with QuotaOwner(config(max_in_flight=1), tmp_path) as owner:
            async def cancelled_operation():
                async with owner.reserve():
                    entered.set()
                    await asyncio.Event().wait()
            async def replacement():
                async with owner.reserve():
                    pytest.fail("cancelled remote work recycled")
            task = asyncio.create_task(cancelled_operation())
            await entered.wait()
            waiter = asyncio.create_task(replacement())
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            with pytest.raises(QuotaQuarantinedError):
                await asyncio.wait_for(waiter, 2)
            assert list(state(tmp_path).values()) == ["quarantined"]
    asyncio.run(scenario())


def test_cancelling_queued_work_creates_no_reservation(tmp_path):
    async def scenario():
        with QuotaOwner(config(max_in_flight=1), tmp_path) as owner:
            async with owner.reserve() as active:
                async def queued():
                    async with owner.reserve():
                        pytest.fail("unexpected admission")
                task = asyncio.create_task(queued())
                await asyncio.sleep(0)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert state(tmp_path) == {active.identifier: "uncertain"}
                active.settle()
            assert state(tmp_path) == {}
    asyncio.run(scenario())


def test_owner_exit_with_active_work_persists_quarantine(tmp_path):
    async def scenario():
        owner = QuotaOwner(config(), tmp_path)
        owner.__enter__()
        reservation_context = owner.reserve()
        reservation = await reservation_context.__aenter__()
        owner.__exit__(None, None, None)
        assert state(tmp_path) == {reservation.identifier: "quarantined"}
        # Late local cleanup must not undo the already closed owner's quarantine.
        reservation.settle()
        await reservation_context.__aexit__(None, None, None)
        assert state(tmp_path) == {reservation.identifier: "quarantined"}
        with pytest.raises(QuotaQuarantinedError):
            with QuotaOwner(config(), tmp_path):
                pass
    asyncio.run(scenario())


def test_quarantine_reduces_capacity_without_recycling(tmp_path):
    async def scenario():
        with QuotaOwner(config(max_in_flight=2), tmp_path) as owner:
            async with owner.reserve() as quarantined:
                pass
            async with owner.reserve() as usable:
                assert state(tmp_path) == {quarantined.identifier: "quarantined",
                                           usable.identifier: "uncertain"}
                usable.settle()
            assert state(tmp_path) == {quarantined.identifier: "quarantined"}
    asyncio.run(scenario())


PROCESS_SCRIPT = '''
import asyncio, os, sys
from pathlib import Path
from taosc_llm.admission import QuotaOwner, QuotaOwnerBusy
from taosc_llm.provider import ProviderConfig
async def run():
    try:
        with QuotaOwner(ProviderConfig(api_key="offline-only"), Path(sys.argv[1])) as owner:
            if sys.argv[2] == "crash":
                async with owner.reserve():
                    os._exit(23)
    except QuotaOwnerBusy:
        sys.exit(19)
asyncio.run(run())
'''


def child(state_dir, mode):
    # Pass import plumbing only, not credentials or the ambient environment.
    source_root = str(Path(__file__).resolve().parents[1] / "src")
    return subprocess.run([sys.executable, "-c", PROCESS_SCRIPT, str(state_dir), mode],
                          env={"PYTHONPATH": source_root}, capture_output=True, timeout=10)


def test_concurrent_process_owner_and_recovery_rejected(tmp_path):
    with QuotaOwner(config(), tmp_path):
        assert child(tmp_path, "enter").returncode == 19
        with pytest.raises(QuotaOwnerBusy):
            with QuotaOwner(config(), tmp_path):
                pass
        with pytest.raises(QuotaOwnerBusy):
            recover_reservations(state_dir=tmp_path, confirm_provider_settled=True)


def test_owner_crash_leaves_durable_uncertain_reservation(tmp_path):
    assert child(tmp_path, "crash").returncode == 23
    persisted = state(tmp_path)
    assert len(persisted) == 1
    assert list(persisted.values()) == ["uncertain"]
    with pytest.raises(QuotaQuarantinedError):
        with QuotaOwner(config(), tmp_path):
            pass
    assert state(tmp_path) == persisted
    recover_reservations(state_dir=tmp_path, confirm_provider_settled=True)
    with QuotaOwner(config(), tmp_path):
        pass


def test_state_is_private_and_has_no_provider_material(tmp_path):
    async def scenario():
        path = tmp_path / "new-private-state"
        with QuotaOwner(config(), path) as owner:
            async with owner.reserve() as reservation:
                assert path.stat().st_mode & 0o777 == 0o700
                for name in ("owner.lock", "reservations.json"):
                    assert (path / name).stat().st_mode & 0o777 == 0o600
                serialized = (path / "reservations.json").read_text()
                assert "offline-test-secret" not in serialized
                assert "ollama" not in serialized
                reservation.settle()
    asyncio.run(scenario())


def test_default_scope_is_stable_not_environment_selected(tmp_path, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr("taosc_llm.admission.pwd.getpwuid",
                        lambda uid: SimpleNamespace(pw_dir=str(tmp_path)))
    monkeypatch.setenv("HOME", str(tmp_path / "home-bypass"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "bypass"))
    monkeypatch.setenv("OPENAI_API_KEY", "different-account")
    expected = tmp_path / ".local" / "state" / "taosc-llm" / "quota"
    with QuotaOwner(config()) as first:
        assert first.state_dir == expected
        with pytest.raises(QuotaOwnerBusy):
            with QuotaOwner(ProviderConfig(api_key="other")):
                pass


@pytest.mark.parametrize("contents", ['{}', 'not json',
    '{"schema_version":1,"reservations":{},"reservations":{}}'])
def test_corrupt_state_fails_closed_even_for_recovery(tmp_path, contents):
    path = tmp_path / "reservations.json"
    path.write_text(contents)
    path.chmod(0o600)
    with pytest.raises(AdmissionError):
        with QuotaOwner(config(), tmp_path):
            pass
    with pytest.raises(AdmissionError):
        recover_reservations(state_dir=tmp_path, confirm_provider_settled=True)


def test_unsafe_state_directory_rejected(tmp_path):
    path = tmp_path / "public"
    path.mkdir(mode=0o755)
    with pytest.raises(AdmissionError):
        with QuotaOwner(config(), path):
            pass
