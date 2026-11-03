"""Host deadlines must retire one REA session, including its detached backend."""
import os
import sys

import pytest
from taosc_llm._rea import ReaSession


def test_request_timeout_cancels_and_waits_for_detached_backend(tmp_path):
    executable = tmp_path / "rea"
    executable.write_text(f"#!{sys.executable}\n" + '''
import json, os, signal, subprocess, sys
from pathlib import Path
child = None
try:
    for line in sys.stdin:
        request = json.loads(line)
        method = request["method"]
        if method == "notifications/cancelled":
            Path("cancelled").write_text(str(request["params"]["requestId"]))
            continue
        if "id" not in request:
            continue
        if method == "initialize":
            result = {"protocolVersion": "2025-11-25", "serverInfo": {"version": "6.8.0"}}
        elif request["params"]["name"] == "open_binary":
            result = {"structuredContent": {"result": {"sha256": "a" * 64}}}
        else:
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
            Path("child-pid").write_text(str(child.pid))
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
finally:
    if child is not None:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
''')
    executable.chmod(0o700)
    with ReaSession(str(executable), tmp_path / "inert", "a" * 64,
                    {"PATH": os.defpath}, tmp_path, timeout=1, query_timeout=1) as session:
        result = session.query("resolve_containing_procedure", 16)
        assert result["ok"] is False and "exceeded" in result["error"]
        # No replacement backend is launched after the live query was cancelled.
        assert session.query("xrefs", 17) == result
        pid = int((tmp_path / "child-pid").read_text())
    assert (tmp_path / "cancelled").read_text() == "3"
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    assert session.process.returncode == 0
