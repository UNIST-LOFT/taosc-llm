"""Real pinned Pi SDK with an in-process fake HTTP transport, never a provider."""

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile
from taosc_llm.bridge import adapter_command, run_adapter
from taosc_llm.context import digest, prepare_context
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
  else if (count <= 2) {
    const name = count === 1 ? 'get_patch_context' : 'check_predicate';
    const args = count === 1 ? {context_id:context} : {context_id:context,jump_if:'rax <= 0'};
    data = chunk({role:'assistant',tool_calls:[{index:0,id:'call-'+count,type:'function',function:{name,arguments:JSON.stringify(args)}}]});
    data += chunk({},'tool_calls') + 'data: [DONE]\n\n';
  } else {
    const proposal = {schema_version:1,context_id:context,decision:'candidate',jump_if:'rax <= 0',evidence_ids:[],assumptions:[],reason:'Offline transport fixture only.'};
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
    config = tmp_path / "config.env"
    config.write_text("BINARY=fixture\n")
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    original = workdir / "fixture.orig"
    shutil.copyfile(sys.executable, original)
    with original.open("rb") as stream:
        entry = ELFFile(stream).header["e_entry"]
    for name in ("patch-location", "patch-destination"):
        (workdir / name).write_text(f"{entry:x}")
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps({"schema_version":1,"origin":"fixture","original_sha256":digest(original.read_bytes()),
                                   "specification":"Offline transport fixture, not an executable repair oracle.",
                                   "destination_semantics":"Caller-selected fixture destination.","functions":[],"observations":[]}))
    return prepare_context(config, workdir, evidence), Path(root)


def operation(adapter_context, tmp_path, mode):
    context, root = adapter_context
    preload = tmp_path / "provider.mjs"
    preload.write_text(PRELOAD.replace("__MODE__", json.dumps(mode)))
    command = adapter_command(root)
    command[1:1] = ["--import", str(preload)]
    provider = ProviderConfig(api_key="offline-secret-for-transport", base_url="https://example.invalid/v1",
                              model="offline-exact-model", timeout_seconds=30)
    settlement = {}
    journal = tmp_path / "turn.jsonl"
    result = asyncio.run(run_adapter(context, provider, command, "offline", journal, settlement))
    assert provider.api_key not in journal.read_text()
    return result, settlement, context


def test_pi_custom_tools_and_settled_final_proposal(adapter_context, tmp_path):
    result, settlement, context = operation(adapter_context, tmp_path, "tools")
    assert result["type"] == "turn_complete", result
    assert settlement == {"remote_settled": True}
    assert result["request_count"] == 3
    assert result["host_inspected_context"] is True
    assert result["host_checked_predicates"] == ["rax <= 0"]
    assert set(result["active_tools"]) == {"get_patch_context", "get_function_context", "list_observations", "get_observation", "check_predicate"}
    assert context.validate_proposal(result["final_text"])["jump_if"] == "rax <= 0"


@pytest.mark.parametrize("mode,status,code", [
    ("rate",429,"provider_rate_limited"),
    ("auth",401,"provider_authentication_failed"),
    ("redirect",302,"provider_redirect_rejected"),
])
def test_pi_http_failures_are_terminal_and_redacted(adapter_context, tmp_path, mode, status, code):
    result, settlement, _ = operation(adapter_context, tmp_path, mode)
    assert result["type"] == "turn_failed"
    assert result["http_status"] == status
    assert result["error_code"] == code
    assert result["request_count"] == 1
    assert settlement == {"remote_settled": True}
    if mode == "rate":
        assert result["retry_after_seconds"] == 2


@pytest.mark.parametrize("mode", ["truncated", "cancel"])
def test_pi_unfinished_transport_is_not_recyclable(adapter_context, tmp_path, mode):
    result, settlement, _ = operation(adapter_context, tmp_path, mode)
    assert result["type"] == "turn_failed"
    assert result["request_count"] == 1
    assert settlement == {"remote_settled": False}
