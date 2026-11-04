"""Real pinned Pi SDK with an in-process fake HTTP transport, never a provider."""

import asyncio
import json
import os
from pathlib import Path

import pytest
from taosc_llm.bridge import adapter_command, run_adapter
from taosc_llm.context import prepare_context
from taosc_llm.provider import ProviderConfig

PRELOAD = r'''
const mode = __MODE__;
let count = 0;
const encode = x => new TextEncoder().encode(x);
globalThis.fetch = async (input, init) => {
  const url = input instanceof Request ? input.url : String(input);
  if (url !== 'https://example.invalid/v1/chat/completions') throw Error('unexpected endpoint');
  const body = JSON.parse(init.body);
  if (body.model !== 'offline-exact-model' || body.tool_choice !== undefined) throw Error('wrong model/protocol');
  count++;
  if (mode === 'rate') return new Response(JSON.stringify({error:{message:'offline-secret-for-transport'}}), {status:429,headers:{'retry-after':'2'}});
  if (mode === 'auth') return new Response(JSON.stringify({error:{message:'offline-secret-for-transport'}}), {status:401});
  if (mode === 'redirect') return new Response('',{status:302,headers:{location:'https://example.invalid/elsewhere'}});
  if (mode === 'cancel') {
    return new Response(new ReadableStream({start(c) {
      init.signal.addEventListener('abort', () => c.error(Error('aborted')), {once:true});
      setImmediate(() => process.kill(process.pid, 'SIGTERM'));
    }}),{headers:{'content-type':'text/event-stream'}});
  }
  const context = JSON.stringify(body.messages).match(/context_id=([a-f0-9]{64})/)[1];
  const chunk = (delta, finish=null) => 'data: ' + JSON.stringify({id:'offline',object:'chat.completion.chunk',created:1,
    model:body.model,choices:[{index:0,delta,finish_reason:finish}]}) + '\n\n';
  let data;
  if (mode === 'truncated') data = chunk({role:'assistant',content:'incomplete'},'stop');
  else if (count <= 2 && mode !== 'abstain') {
    const name = count === 1 ? 'get_patch_context' : 'evaluate_predicate';
    const args = count === 1 ? {context_id:context} : {context_id:context,predicate:'rax <= 0'};
    data = chunk({role:'assistant',tool_calls:[{index:0,id:'call-'+count,type:'function',function:{name,arguments:JSON.stringify(args)}}]});
    data += chunk({},'tool_calls') + 'data: [DONE]\n\n';
  } else if (count === 3 && mode === 'results') {
    const tool = body.messages.filter(m => m.role === 'tool').at(-1);
    const result = JSON.parse(typeof tool.content === 'string' ? tool.content : tool.content[0].text);
    if (!result.ok || !result.result_id) throw Error('missing host result');
    const args = {context_id:context,result_id:result.result_id};
    data = chunk({role:'assistant',tool_calls:[{index:0,id:'result-call',type:'function',function:{name:'get_candidate_result',arguments:JSON.stringify(args)}}]});
    data += chunk({},'tool_calls') + 'data: [DONE]\n\n';
  } else {
    const proposal = {schema_version:1,context_id:context,decision:mode === 'abstain' ? 'abstain' : 'candidate',predicate:mode === 'abstain' ? null : 'rax <= 0',evidence_ids:[],assumptions:[],reason:'Offline transport fixture only.'};
    data = chunk({role:'assistant',content:JSON.stringify(proposal)}) + chunk({},'stop') + 'data: [DONE]\n\n';
  }
  return new Response(new ReadableStream({start(c){c.enqueue(encode(data));c.close();}}),{headers:{'content-type':'text/event-stream'}});
};
'''


@pytest.fixture
def adapter_context(tmp_path):
    root = os.environ.get("TAOSC_LLM_PI_SDK_ROOT")
    if not root:
        pytest.skip("set TAOSC_LLM_PI_SDK_ROOT for offline pinned-SDK tests")
    from test_context_tools import make_dataset
    return prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "run"), Path(root)


def operation(adapter_context, tmp_path, mode):
    context, root = adapter_context
    preload = tmp_path / "provider.mjs"
    preload.write_text(PRELOAD.replace("__MODE__", json.dumps(mode)))
    command = adapter_command(root)
    command[1:1] = ["--import", str(preload)]
    provider = ProviderConfig(api_key="offline-secret-for-transport", base_url="https://example.invalid/v1",
                              model="offline-exact-model", timeout_seconds=30)
    journal = tmp_path / "turn.jsonl"
    result = asyncio.run(run_adapter(context, provider, command, "offline", journal))
    assert provider.api_key not in journal.read_text()
    return result, context


def test_pi_custom_tools_and_settled_final_proposal(adapter_context, tmp_path):
    result, context = operation(adapter_context, tmp_path, "tools")
    assert result["type"] == "turn_complete", result
    assert result["remote_settled"] is True
    assert result["request_count"] == 3
    assert result["host_inspected_context"] is True
    assert result["host_checked_predicates"] == ["rax <= 0"]
    assert set(result["active_tools"]) == {"get_patch_context", "get_function_analysis", "list_cases", "get_case", "evaluate_predicate", "test_candidate", "get_candidate_result"}
    assert context.validate_proposal(result["final_text"])["predicate"] == "rax <= 0"


def test_pi_continues_after_actual_offline_result_reference(adapter_context, tmp_path):
    result, context = operation(adapter_context, tmp_path, "results")
    assert result["type"] == "turn_complete"
    assert result["request_count"] == 4
    assert result["tool_calls"] == 3
    assert result["remote_settled"] is True
    assert context._results
    assert all(item["verified"] is False for item in context._results.values())


@pytest.mark.parametrize("mode,status,code", [
    ("rate",429,"provider_rate_limited"),
    ("auth",401,"provider_authentication_failed"),
    ("redirect",302,"provider_redirect_rejected"),
])
def test_pi_http_failures_are_terminal_and_redacted(adapter_context, tmp_path, mode, status, code):
    result, _ = operation(adapter_context, tmp_path, mode)
    assert result["type"] == "turn_failed"
    assert result["http_status"] == status
    assert result["error_code"] == code
    assert result["request_count"] == 1
    assert result["remote_settled"] is True
    if mode == "rate":
        assert result["retry_after_seconds"] == 2


@pytest.mark.parametrize("held_lock", [False, True])
def test_synthesis_processes_ignore_legacy_global_state(adapter_context, tmp_path, held_lock):
    import fcntl
    import subprocess
    import sys
    from taosc_llm import synthesis

    context, root = adapter_context
    home = tmp_path / "fake-home"
    quota = home / ".local" / "state" / "taosc-llm" / "quota"
    quota.mkdir(mode=0o700, parents=True)
    ledger = quota / "reservations.json"
    ledger.write_text(json.dumps({"schema_version": 1, "reservations": {
        "legacy-uncertain": "uncertain", "legacy-quarantined": "quarantined"}}))
    ledger.chmod(0o600)
    lock = quota / "owner.lock"
    lock.write_bytes(b"legacy-lock-untouched")
    lock.chmod(0o600)
    before = {path.name: path.read_bytes() for path in quota.iterdir()}
    rendezvous = tmp_path / "overlapping-fetches"
    rendezvous.mkdir()
    preload = tmp_path / "concurrent-provider.mjs"
    # Neither process can finish its one fake fetch until both have entered it.
    # A shared cross-process admission lock would fail this barrier.
    barrier = r'''
  const fs = await import('node:fs');
  const directory = __RENDEZVOUS__;
  fs.writeFileSync(directory + '/' + process.pid, 'entered');
  const deadline = Date.now() + 10000;
  while (fs.readdirSync(directory).length < 2) {
    if (Date.now() > deadline) throw Error('synthesis processes did not overlap');
    await new Promise(resolve => setTimeout(resolve, 10));
  }
'''.replace("__RENDEZVOUS__", json.dumps(str(rendezvous)))
    preload.write_text(PRELOAD.replace("__MODE__", '"abstain"').replace("  count++;", "  count++;" + barrier))
    provider_file = tmp_path / "offline-provider.conf"
    provider_file.write_text('TAOSC_LLM_PROFILE=openai-compatible\n'
                             'OPENAI_API_KEY=offline-secret-for-transport\n'
                             'OPENAI_BASE_URL=https://example.invalid/v1\n'
                             'OPENAI_MODEL=offline-exact-model\n'
                             'TAOSC_LLM_TIMEOUT_SECONDS=30\n')
    code = r'''import json, os, pwd, sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
from taosc_llm import synthesis
home, dataset, provider, root, preload, output = map(Path, sys.argv[2:])
os.environ['HOME'] = str(home)
original = synthesis.adapter_command
def offline_command(root):
    command = original(root)
    command[1:1] = ['--import', str(preload)]
    return command
# The removed quota implementation used passwd, not HOME. Redirect both so a
# regression cannot accidentally consult or mutate the actual account state.
with patch.object(pwd, 'getpwuid', return_value=SimpleNamespace(pw_dir=str(home))), \
     patch.object(synthesis, 'adapter_command', offline_command):
    result = synthesis.generate_with_pi(dataset, provider, sdk_root=root,
                                        output=output, max_rounds=1)
print(json.dumps(result))
'''
    processes = []
    with lock.open("rb") as held:
        if held_lock:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            for index in range(2):
                processes.append(subprocess.Popen(
                    [sys.executable, "-I", "-c", code,
                     str(Path(synthesis.__file__).resolve().parent.parent), str(home),
                     str(tmp_path / "dataset"), str(provider_file), str(root), str(preload),
                     str(tmp_path / f"independent-run-{index}")],
                    cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
            results = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=60)
                assert process.returncode == 0, stderr
                results.append(json.loads(stdout))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait()
    assert len(list(rendezvous.iterdir())) == 2
    assert len({result["run_id"] for result in results}) == 2
    for result in results:
        assert result["status"] == "abstained"
        assert result["verified"] is False
        assert result["binradar_verification"] == "not_run"
        assert len(result["attempts"]) == 1
        assert result["attempts"][0]["request_count"] == 1
        assert result["attempts"][0]["remote_settled"] is True
        record = Path(result["run_directory"]) / "run.json"
        assert json.loads(record.read_text())["status"] == "abstained"
        journal = record.parent / "trials" / "1" / "turn-1.jsonl"
        assert "offline-secret-for-transport" not in journal.read_text()
    assert {path.name: path.read_bytes() for path in quota.iterdir()} == before


@pytest.mark.parametrize("mode", ["truncated", "cancel"])
def test_pi_unfinished_transport_remains_unsettled(adapter_context, tmp_path, mode):
    result, _ = operation(adapter_context, tmp_path, mode)
    assert result["type"] == "turn_failed"
    assert result["request_count"] == 1
    assert result["remote_settled"] is False
