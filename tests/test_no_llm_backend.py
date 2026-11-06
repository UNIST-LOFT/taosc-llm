"""Persistent admission budgets cannot be replenished by process interruption."""
from types import SimpleNamespace

import pytest

from taosc_llm.no_llm import backend as module
from taosc_llm.no_llm.backend import Backend
from taosc_llm.no_llm.journal import Journal
from taosc_llm.no_llm.model import SearchLimits, SearchStopped


@pytest.mark.parametrize("closed,expected", [(False, 25.0), (True, 5.0)])
def test_resume_charges_unclosed_interval_but_not_clean_downtime(tmp_path, monkeypatch, closed, expected):
    clock = {"wall": 100.0, "monotonic": 50.0}
    monkeypatch.setattr(module.time, "time", lambda: clock["wall"])
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["monotonic"])
    limits = SearchLimits(timeout=20, max_evaluations=2, max_executions=10)
    output = tmp_path / "search"
    with Journal(output, {"case": "budget"}) as journal:
        backend = Backend(SimpleNamespace(), journal, limits)
        backend.reserve(7)
        clock.update(wall=105.0, monotonic=55.0)
        backend.checkpoint_budget()
        if closed:
            journal.append("session_closed", {})
    clock.update(wall=125.0, monotonic=75.0)
    with Journal(output, {"case": "budget"}, resume=True) as journal:
        resumed = Backend(SimpleNamespace(), journal, limits)
        assert resumed.elapsed == expected
        assert resumed.evaluations == 1
        assert resumed.executions_reserved == 7
        with pytest.raises(SearchStopped, match="execution-budget" if closed else "wall-time"):
            resumed.reserve(4)
        assert resumed.executions_reserved == 7
