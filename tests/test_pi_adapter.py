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
  else if (count <= 2) {
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
    const proposal = {schema_version:1,context_id:context,decision:'candidate',predicate:'rax <= 0',evidence_ids:[],assumptions:[],reason:'Offline transport fixture only.'};
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
    assert set(result["active_tools"]) == {"get_patch_context", "get_function_analysis", "list_cases", "get_case", "evaluate_predicate", "test_candidate", "get_candidate_result"}
    assert context.validate_proposal(result["final_text"])["predicate"] == "rax <= 0"


def test_pi_continues_after_actual_offline_result_reference(adapter_context, tmp_path):
    result, settlement, context = operation(adapter_context, tmp_path, "results")
    assert result["type"] == "turn_complete"
    assert result["request_count"] == 4
    assert result["tool_calls"] == 3
    assert settlement["remote_settled"] is True
    assert context._results
    assert all(item["verified"] is False for item in context._results.values())


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
