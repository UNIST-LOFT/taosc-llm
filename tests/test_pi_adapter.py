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
const streamEnd = __STREAM_END__;
const reasoningEffort = __REASONING_EFFORT__;
let count = 0;
const encode = x => new TextEncoder().encode(x);
let expireDeadlines;
if (mode === 'feedback-deadline') {
  // Drive only the configured 30-second deadlines at protocol boundaries.
  // SDK import speed and host load must not decide this lifecycle regression.
  const schedule = globalThis.setTimeout, cancel = globalThis.clearTimeout;
  const deadlines = new Set();
  globalThis.setTimeout = (callback, milliseconds, ...args) => {
    if (milliseconds !== 30000) return schedule(callback, milliseconds, ...args);
    const timer = {callback: () => callback(...args), unref() { return this; }};
    deadlines.add(timer);
    return timer;
  };
  globalThis.clearTimeout = timer => {
    if (!deadlines.delete(timer)) cancel(timer);
  };
  expireDeadlines = () => {
    const expired = [...deadlines]; deadlines.clear();
    for (const timer of expired) timer.callback();
  };
  process.stdin.on('data', data => {
    // An uncleared synthesis deadline would fail before review admission.
    if (data.toString().includes('"type":"host_outcome"')) expireDeadlines();
  });
}
if (mode === 'write-failure') {
  const {default:fs} = await import('node:fs');
  const {syncBuiltinESMExports} = await import('node:module');
  const originalWrite = fs.writeSync;
  fs.writeSync = function(fd, ...args) {
    if (fs.readlinkSync('/proc/self/fd/' + fd).endsWith('.errors/request-1.body')) {
      throw Object.assign(new Error('offline diagnostic disk full'), {code:'ENOSPC'});
    }
    return originalWrite.call(this, fd, ...args);
  };
  syncBuiltinESMExports();
}
globalThis.fetch = async (input, init) => {
  const url = input instanceof Request ? input.url : String(input);
  if (url !== 'https://example.invalid/v1/chat/completions') throw Error('unexpected endpoint');
  const body = JSON.parse(init.body);
  if (body.model !== 'offline-exact-model' || body.tool_choice !== undefined) throw Error('wrong model/protocol');
  if (body.reasoning_effort !== (reasoningEffort ?? undefined)) throw Error('reasoning effort changed or omitted');
  count++;
  const reviewing = JSON.stringify(body.messages.at(-1)).includes('Host review phase:');
  if (reviewing) {
    if (body.tools !== undefined) throw Error('review offered executable tools');
    if (!JSON.stringify(body.messages).includes('Offline transport fixture only.')) throw Error('original proposal history missing');
    if (mode === 'feedback-auth') return new Response('{"error":{"message":"review denied"}}', {status:401});
    if (mode === 'feedback-cancel' || mode === 'feedback-timeout' || mode === 'feedback-deadline') {
      return new Response(new ReadableStream({start(c) {
        init.signal.addEventListener('abort', () => c.error(Error('aborted')), {once:true});
        if (mode === 'feedback-deadline') setImmediate(expireDeadlines);
        if (mode === 'feedback-cancel') setImmediate(() => process.kill(process.pid, 'SIGTERM'));
      }}), {headers:{'content-type':'text/event-stream'}});
    }
    const delta = mode === 'feedback-tool' ? {role:'assistant',tool_calls:[{index:0,id:'forbidden',type:'function',
      function:{name:'get_patch_context',arguments:'{}'}}]} : {role:'assistant',content:'# Session review\n\nEvidence was bounded; activation is distinct from outcome.'};
    const event = {id:'review',object:'chat.completion.chunk',created:1,model:body.model,
      choices:[{index:0,delta,finish_reason:null}]};
    const end = {...event,choices:[{index:0,delta:{},finish_reason:mode === 'feedback-tool' ? 'tool_calls' : 'stop'}],
      usage:{prompt_tokens:11,completion_tokens:7,total_tokens:18}};
    return new Response('data: '+JSON.stringify(event)+'\n\ndata: '+JSON.stringify(end)+'\n\ndata: [DONE]\n\n',
      {headers:{'content-type':'text/event-stream'}});
  }
  if (mode === 'rate') return new Response(JSON.stringify({error:{message:'offline-secret-for-transport'}}), {status:429,headers:{'retry-after':'2'}});
  if (mode === 'auth' || mode === 'write-failure' || (mode === 'failure-prefix' && count === 2)) return new Response(JSON.stringify({error:{message:'private-provider-body offline-secret-for-transport',detail:'private-response-detail'}}), {status:401});
  if (mode === 'checkpoint') {
    // Let the public message_end callback's deferred checkpoint run before
    // inspecting the sidecar while the next provider request is still active.
    await new Promise(resolve => setImmediate(resolve));
    const fs = await import('node:fs');
    const session = __SESSION_PATH__;
    fs.writeFileSync(session + (count === 1 ? '.initial' : '.live'), fs.readFileSync(session));
    if (count === 2) return new Response(new ReadableStream({start(c) {
      init.signal.addEventListener('abort', () => c.error(Error('aborted')), {once:true});
      setImmediate(() => process.kill(process.pid, 'SIGTERM'));
    }}),{headers:{'content-type':'text/event-stream'}});
  }
  if (mode === 'context-limit') return new Response(JSON.stringify({error:{code:'context_length_exceeded',message:'maximum context length exceeded: private context detail offline-secret-for-transport'}}), {status:400});
  if (mode === 'binary') return new Response(new Uint8Array([0,255,128,13,10,65,0]), {status:502,headers:{'content-type':'application/octet-stream'}});
  if (mode === 'large') return new Response('private-large-body offline-secret-for-transport\n' + 'x'.repeat(4 * 1024 * 1024 + 137), {status:503});
  if (mode === 'network') throw new TypeError('private network detail offline-secret-for-transport', {cause:new Error('private socket cause')});
  if (mode === 'partial-cancel') {
    let pulls = 0;
    return new Response(new ReadableStream({pull(c) {
      if (pulls++ === 0) c.enqueue(encode('cancelled-body offline-secret-for-transport\n'));
      else return new Promise(resolve => {
        init.signal.addEventListener('abort', () => {
          c.error(new Error('offline transfer cancelled')); resolve();
        }, {once:true});
        setImmediate(() => process.kill(process.pid, 'SIGTERM'));
      });
    }}), {status:502});
  }
  if (mode === 'partial') {
    let pulls = 0;
    return new Response(new ReadableStream({pull(c) {
      if (pulls++ === 0) c.enqueue(encode('partial-body offline-secret-for-transport\n'));
      else c.error(new Error('private interrupted transfer', {cause:new Error('private stream cause')}));
    }}), {status:502});
  }
  if (mode === 'redirect') return new Response('private redirect body offline-secret-for-transport',{status:302,headers:{location:'https://example.invalid/elsewhere'}});
  if (mode === 'cancel') {
    return new Response(new ReadableStream({start(c) {
      init.signal.addEventListener('abort', () => c.error(Error('aborted')), {once:true});
      setImmediate(() => process.kill(process.pid, 'SIGTERM'));
    }}),{headers:{'content-type':'text/event-stream'}});
  }
  const context = JSON.stringify(body.messages).match(/context_id=([a-f0-9]{64})/)[1];
  const chunk = (delta, finish=null) => 'data: ' + JSON.stringify({id:'offline',object:'chat.completion.chunk',created:1,
    model:body.model,choices:[{index:0,delta,finish_reason:finish}],
    ...(finish ? {usage:{prompt_tokens:11,completion_tokens:7,total_tokens:18}} : {})}) + '\n\n';
  let data;
  if (mode === 'missing-finish') data = chunk({role:'assistant',content:'incomplete'}) + 'data: [DONE]\n\n';
  else if (mode === 'truncated') data = chunk({role:'assistant',content:'incomplete'},'stop');
  else if (count <= 2 && mode !== 'abstain') {
    const name = count === 1 ? 'get_patch_context' : 'evaluate_predicate';
    const args = count === 1 ? {context_id:context} : {context_id:context,predicate:'rax <= 0'};
    data = chunk({role:'assistant',content:'Intermediate explanation '+count,reasoning_content:'Intermediate reasoning '+count,
      tool_calls:[{index:0,id:'call-'+count,type:'function',function:{name,arguments:JSON.stringify(args)}}]});
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
  return new Response(new ReadableStream({
    start(c) { c.enqueue(encode(data)); if (streamEnd === 'eof') c.close(); },
    cancel() {
      if (streamEnd === 'cancel-error') {
        throw new Error('private cancellation failure', {cause:new Error('private cancellation cause')});
      }
    },
  }), {headers:{'content-type':'text/event-stream'}});
};
'''


@pytest.fixture
def adapter_context(tmp_path):
    root = os.environ.get("TAOSC_LLM_PI_SDK_ROOT")
    if not root:
        pytest.skip("set TAOSC_LLM_PI_SDK_ROOT for offline pinned-SDK tests")
    from test_context_tools import make_dataset
    return prepare_context(make_dataset(tmp_path / "dataset"), run_dir=tmp_path / "run"), Path(root)


def operation(adapter_context, tmp_path, mode, *, journal=None,
              api_key="offline-secret-for-transport", stream_end="eof", reasoning_effort=None,
              on_complete=None, timeout_seconds=30):
    context, root = adapter_context
    journal = journal if journal is not None else tmp_path / "turn.jsonl"
    preload = tmp_path / "provider.mjs"
    preload.write_text(PRELOAD.replace("__MODE__", json.dumps(mode))
                       .replace("__STREAM_END__", json.dumps(stream_end))
                       .replace("__REASONING_EFFORT__", json.dumps(reasoning_effort))
                       .replace("__SESSION_PATH__", json.dumps(str(journal.with_suffix(".pi.jsonl")))))
    command = adapter_command(root)
    command[1:1] = ["--import", str(preload)]
    provider = ProviderConfig(api_key=api_key, base_url="https://example.invalid/v1",
                              model="offline-exact-model", timeout_seconds=timeout_seconds,
                              reasoning_effort=reasoning_effort)
    result = asyncio.run(run_adapter(context, provider, command, "offline", journal,
                                    on_complete=on_complete))
    assert provider.api_key not in journal.read_text()
    return result, context


def native_records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def assert_error_body(directory, expected, *, status, request_index=1, complete=True):
    assert directory.stat().st_mode & 0o777 == 0o700
    events_path = directory / "events.jsonl"
    body_path = directory / f"request-{request_index}.body"
    assert events_path.stat().st_mode & 0o777 == 0o600
    assert body_path.stat().st_mode & 0o777 == 0o600
    assert body_path.read_bytes() == expected
    events = native_records(events_path)
    responses = [event for event in events if event["type"] == "http_response"]
    assert len(responses) == 1
    assert responses[0]["request_index"] == request_index
    assert responses[0]["status"] == status
    assert isinstance(responses[0]["status_text"], str)
    assert responses[0]["body_file"] == body_path.name
    endings = [event for event in events if event["type"] == "http_body_end"]
    assert endings == [{"type": "http_body_end", "request_index": request_index,
                        "complete": complete, "body_bytes": len(expected)}]
    return events


def load_native_session(root, path, *, export=False):
    """Use the pinned SDK's public reader and real standalone HTML exporter."""
    import subprocess

    package = root / "node_modules" / "@earendil-works" / "pi-coding-agent"
    metadata = json.loads((package / "package.json").read_text())
    entry = package / metadata["exports"]["."]["import"]
    exporter = package / "dist" / "core" / "export-html" / "index.js"
    code = r'''
globalThis.fetch = () => { throw Error('native consumer must remain offline'); };
const {SessionManager} = await import(process.argv[1]);
const session = SessionManager.open(process.argv[3]);
if (process.argv[4] === 'export') {
  const {exportFromFile} = await import(process.argv[2]);
  await exportFromFile(process.argv[3], {outputPath:process.argv[3]+'.html'});
}
console.log(JSON.stringify({header:session.getHeader(),entries:session.getEntries(),
  messages:session.buildSessionContext().messages}));
'''
    completed = subprocess.run(
        [adapter_command(root)[0], "--input-type=module", "-e", code,
         entry.resolve().as_uri(), exporter.resolve().as_uri(), str(path),
         "export" if export else "load"],
        capture_output=True, text=True, check=True, timeout=30)
    return json.loads(completed.stdout)


@pytest.mark.parametrize("stream_end", ["eof", "pending"])
def test_pi_custom_tools_and_settled_final_proposal(adapter_context, tmp_path, stream_end):
    result, context = operation(adapter_context, tmp_path, "tools", stream_end=stream_end)
    assert result["type"] == "turn_complete", result
    assert result["remote_settled"] is True
    assert result["request_count"] == 3
    assert result["host_inspected_context"] is True
    assert result["host_checked_predicates"] == ["rax <= 0"]
    assert set(result["active_tools"]) == {"get_patch_context", "get_function_analysis", "list_cases", "get_case", "evaluate_predicate", "test_candidate", "get_candidate_result"}
    assert context.validate_proposal(result["final_text"])["predicate"] == "rax <= 0"
    assert result["usage"] == {"scope": "all_requests", "input": 33, "output": 21, "totalTokens": 54}
    assert not (tmp_path / "turn.errors").exists()


@pytest.mark.parametrize("effort", ["xhigh", "max"])
def test_pi_extended_reasoning_effort_is_not_clamped(adapter_context, tmp_path, effort):
    result, context = operation(adapter_context, tmp_path, "tools",
                                stream_end="pending", reasoning_effort=effort)
    assert result["type"] == "turn_complete", result
    assert result["remote_settled"] is True
    assert result["request_count"] == 3
    assert context.validate_proposal(result["final_text"])["predicate"] == "rax <= 0"
    assert not (tmp_path / "turn.errors").exists()


def test_pi_continues_after_actual_offline_result_reference(adapter_context, tmp_path):
    result, context = operation(adapter_context, tmp_path, "results")
    assert result["type"] == "turn_complete"
    assert result["request_count"] == 4
    assert result["tool_calls"] == 3
    assert result["remote_settled"] is True
    assert context._results
    assert all(item["verified"] is False for item in context._results.values())

    sidecar = tmp_path / "turn.pi.jsonl"
    assert sidecar.stat().st_mode & 0o777 == 0o600
    records = native_records(sidecar)
    loaded = load_native_session(adapter_context[1], sidecar, export=True)
    assert loaded["header"] == records[0]
    assert loaded["header"]["type"] == "session"
    assert loaded["header"]["version"] == 3
    assert loaded["entries"] == records[1:]
    entries = loaded["entries"]
    assert len({entry["id"] for entry in entries}) == len(entries)
    assert [entry["parentId"] for entry in entries] == [None] + [entry["id"] for entry in entries[:-1]]
    messages = [entry["message"] for entry in entries if entry["type"] == "message"]
    assert [message["role"] for message in messages] == [
        "system", "user", "assistant", "toolResult", "assistant", "toolResult",
        "assistant", "toolResult", "assistant"]
    assert json.dumps(context.system_prompt(), ensure_ascii=False)[1:-1] in json.dumps(messages[0], ensure_ascii=False)
    assert {tool["name"] for tool in messages[0]["toolsAdded"]} == {
        tool["name"] for tool in context.tool_definitions()}
    for index, message in enumerate((messages[2], messages[4]), start=1):
        assert {"type": "text", "text": f"Intermediate explanation {index}"} in message["content"]
        assert any(block["type"] == "thinking" and block["thinking"] == f"Intermediate reasoning {index}"
                   for block in message["content"])
    calls = [block for message in messages if message["role"] == "assistant"
             for block in message["content"] if block["type"] == "toolCall"]
    replies = [message for message in messages if message["role"] == "toolResult"]
    assert [call["name"] for call in calls] == ["get_patch_context", "evaluate_predicate", "get_candidate_result"]
    assert [reply["toolCallId"] for reply in replies] == [call["id"] for call in calls]
    assert all(call["arguments"]["context_id"] == context.context_id for call in calls)
    host_results = [record["frame"]["result"] for record in native_records(tmp_path / "turn.jsonl")
                    if record["direction"] == "host" and record["frame"]["type"] == "tool_result"]
    assert [json.loads(reply["content"][0]["text"]) for reply in replies] == host_results
    assert all(result_id in json.dumps(replies) for result_id in context._results)
    assert messages[-1]["content"] == [{"type": "text", "text": result["final_text"]}]
    for message in messages:
        if message["role"] == "assistant":
            assert message["usage"]["input"] == 11
            assert message["usage"]["output"] == 7
    # The SDK reader/exporter must not rewrite the original capture.
    assert native_records(sidecar) == records


@pytest.mark.parametrize("mode,status,code", [
    ("rate",429,"provider_rate_limited"),
    ("auth",401,"provider_authentication_failed"),
    ("redirect",302,"provider_redirect_rejected"),
])
def test_pi_http_failures_keep_private_bodies_and_safe_terminal(adapter_context, tmp_path, mode, status, code):
    result, _ = operation(adapter_context, tmp_path, mode)
    assert result["type"] == "turn_failed"
    assert result["http_status"] == status
    assert result["error_code"] == code
    assert result["request_count"] == 1
    assert result["remote_settled"] is True
    if mode == "rate":
        assert result["retry_after_seconds"] == 2
    sidecar = tmp_path / "turn.pi.jsonl"
    expected = {
        "rate": b'{"error":{"message":"offline-secret-for-transport"}}',
        "auth": b'{"error":{"message":"private-provider-body offline-secret-for-transport","detail":"private-response-detail"}}',
        "redirect": b'private redirect body offline-secret-for-transport',
    }[mode]
    events = assert_error_body(tmp_path / "turn.errors", expected, status=status)
    response = next(event for event in events if event["type"] == "http_response")
    assert response["url"] == "https://example.invalid/v1/chat/completions"
    if mode == "rate":
        assert ["retry-after", "2"] in response["headers"]
    if mode == "redirect":
        assert ["location", "https://example.invalid/elsewhere"] in response["headers"]
    loaded = load_native_session(adapter_context[1], sidecar)
    assert any(message["role"] == "user" for message in loaded["messages"])
    if mode in ("auth", "rate"):
        errors = [entry["message"]["errorMessage"] for entry in loaded["entries"]
                  if entry["type"] == "message" and entry["message"].get("errorMessage")]
        assert len(errors) == 1
        assert "offline-secret-for-transport" in errors[0]
        assert errors[0] != "provider_error"
        if mode == "auth":
            assert "private-provider-body" in errors[0]
            assert "private-response-detail" in (tmp_path / "turn.errors" / "request-1.body").read_text()


@pytest.mark.parametrize("mode", ["checkpoint", "failure-prefix"])
def test_native_completed_prefix_survives_cancel_or_provider_failure(adapter_context, tmp_path, mode):
    result, _ = operation(adapter_context, tmp_path, mode)
    assert result["type"] == "turn_failed"
    assert result["request_count"] == 2
    sidecar = tmp_path / "turn.pi.jsonl"
    if mode == "checkpoint":
        initial = sidecar.with_suffix(".jsonl.initial")
        live = sidecar.with_suffix(".jsonl.live")
        initial_messages = [entry["message"] for entry in native_records(initial)
                            if entry["type"] == "message"]
        assert [message["role"] for message in initial_messages] == ["system", "user"]
        live_messages = [entry["message"] for entry in native_records(live)
                         if entry["type"] == "message"]
        assert [message["role"] for message in live_messages] == ["system", "user", "assistant", "toolResult"]
        assert sidecar.read_bytes().startswith(live.read_bytes())
        assert live.read_bytes().startswith(initial.read_bytes())
        assert result["remote_settled"] is False
    else:
        assert result["error_code"] == "provider_authentication_failed"
        assert result["remote_settled"] is True
    loaded = load_native_session(adapter_context[1], sidecar, export=True)
    messages = [entry["message"] for entry in loaded["entries"] if entry["type"] == "message"]
    completed = next(message for message in messages if message["role"] == "assistant")
    assert {"type": "text", "text": "Intermediate explanation 1"} in completed["content"]
    reply = next(message for message in messages if message["role"] == "toolResult")
    call = next(block for block in completed["content"] if block["type"] == "toolCall")
    assert reply["toolCallId"] == call["id"]
    assert sidecar.stat().st_mode & 0o777 == 0o600
    if mode == "failure-prefix":
        errors = [message["errorMessage"] for message in messages if message.get("errorMessage")]
        assert len(errors) == 1
        assert "private-provider-body offline-secret-for-transport" in errors[0]
        assert_error_body(tmp_path / "turn.errors",
                          b'{"error":{"message":"private-provider-body offline-secret-for-transport","detail":"private-response-detail"}}',
                          status=401, request_index=2)


@pytest.mark.parametrize("mode,status,expected", [
    ("context-limit", 400, b'{"error":{"code":"context_length_exceeded","message":"maximum context length exceeded: private context detail offline-secret-for-transport"}}'),
    ("binary", 502, bytes([0, 255, 128, 13, 10, 65, 0])),
    ("large", 503, b'private-large-body offline-secret-for-transport\n' + b'x' * (4 * 1024 * 1024 + 137)),
])
def test_private_http_payloads_are_byte_complete(adapter_context, tmp_path, mode, status, expected):
    result, _ = operation(adapter_context, tmp_path, mode)
    assert result["type"] == "turn_failed"
    assert result["http_status"] == status
    assert result["request_count"] == 1
    assert result["remote_settled"] is True
    assert_error_body(tmp_path / "turn.errors", expected, status=status)
    if mode == "context-limit":
        loaded = load_native_session(adapter_context[1], tmp_path / "turn.pi.jsonl")
        errors = [entry["message"]["errorMessage"] for entry in loaded["entries"]
                  if entry["type"] == "message" and entry["message"].get("errorMessage")]
        assert len(errors) == 1
        assert "maximum context length exceeded" in errors[0]
        assert "offline-secret-for-transport" in errors[0]


@pytest.mark.parametrize("mode", ["partial", "network"])
def test_private_transport_errors_retain_stack_and_cause(adapter_context, tmp_path, mode):
    result, _ = operation(adapter_context, tmp_path, mode)
    assert result["type"] == "turn_failed"
    assert result["request_count"] == 1
    assert result["remote_settled"] is False
    directory = tmp_path / "turn.errors"
    if mode == "partial":
        events = assert_error_body(directory, b'partial-body offline-secret-for-transport\n',
                                   status=502, complete=False)
        details = ("private interrupted transfer", "private stream cause")
    else:
        assert directory.stat().st_mode & 0o777 == 0o700
        assert (directory / "events.jsonl").stat().st_mode & 0o777 == 0o600
        events = native_records(directory / "events.jsonl")
        assert not list(directory.glob("request-*.body"))
        details = ("private network detail offline-secret-for-transport", "private socket cause")
    errors = [event for event in events if event["type"] == "transport_error"]
    assert len(errors) == 1
    assert errors[0]["request_index"] == 1
    assert all(detail in errors[0]["error"] for detail in details)
    assert "at " in errors[0]["error"]


def test_failed_stream_cancellation_remains_unsettled(adapter_context, tmp_path):
    result, _ = operation(adapter_context, tmp_path, "abstain", stream_end="cancel-error")
    assert result["type"] == "turn_failed"
    assert result["remote_settled"] is False
    assert result["request_count"] == 1
    events = native_records(tmp_path / "turn.errors" / "events.jsonl")
    errors = [event for event in events if event["type"] == "transport_error"]
    assert len(errors) == 1
    assert "private cancellation failure" in errors[0]["error"]
    assert "private cancellation cause" in errors[0]["error"]


def test_partial_http_body_survives_cancellation(adapter_context, tmp_path):
    result, _ = operation(adapter_context, tmp_path, "partial-cancel")
    assert result["type"] == "turn_failed"
    assert result["request_count"] == 1
    assert result["remote_settled"] is False
    assert_error_body(tmp_path / "turn.errors", b'cancelled-body offline-secret-for-transport\n',
                      status=502, complete=False)


def test_failed_diagnostic_write_is_terminal_and_observable(adapter_context, tmp_path):
    result, _ = operation(adapter_context, tmp_path, "write-failure")
    assert result["type"] == "turn_failed"
    assert result["error_code"] == "diagnostic_persistence_error"
    assert result["request_count"] == 1
    directory = tmp_path / "turn.errors"
    assert directory.stat().st_mode & 0o777 == 0o700
    assert (directory / "request-1.body").read_bytes() == b""
    events = native_records(directory / "events.jsonl")
    assert any(event["type"] == "http_response" for event in events)
    assert not any(event["type"] == "http_body_end" and event["complete"] for event in events)


@pytest.mark.parametrize("symlink", [False, True])
def test_error_directory_is_exclusive_and_never_clobbered(adapter_context, tmp_path, symlink):
    directory = tmp_path / "turn.errors"
    target = tmp_path / "prior-errors" if symlink else directory
    target.mkdir()
    original = b'private prior diagnostic: must not be changed\n'
    (target / "events.jsonl").write_bytes(original)
    (target / "request-1.body").write_bytes(original)
    if symlink:
        directory.symlink_to(target, target_is_directory=True)
    result, _ = operation(adapter_context, tmp_path, "auth")
    assert result["type"] == "turn_failed"
    assert result["error_code"] == "diagnostic_persistence_error"
    assert result["request_count"] == 1
    assert directory.is_symlink() is symlink
    assert {path.name: path.read_bytes() for path in target.iterdir()} == {
        "events.jsonl": original, "request-1.body": original}


@pytest.mark.parametrize("symlink", [False, True])
def test_native_destination_is_exclusive_and_never_clobbered(adapter_context, tmp_path, symlink):
    sidecar = tmp_path / "turn.pi.jsonl"
    original = b"private prior run: must not be changed\n"
    if symlink:
        target = tmp_path / "prior-session.jsonl"
        target.write_bytes(original)
        sidecar.symlink_to(target)
    else:
        sidecar.write_bytes(original)
    result, _ = operation(adapter_context, tmp_path, "abstain")
    assert result["type"] == "turn_failed"
    assert result["error_code"] == "session_persistence_error"
    assert result["request_count"] == 0
    assert sidecar.read_bytes() == original
    assert sidecar.is_symlink() is symlink


def test_native_attempts_have_distinct_sessions_and_preserve_prior_capture(adapter_context, tmp_path):
    first = tmp_path / "turn-1.jsonl"
    second = tmp_path / "turn-2.jsonl"
    failed, _ = operation(adapter_context, tmp_path, "auth", journal=first)
    original_journal = first.read_bytes()
    original_native = first.with_suffix(".pi.jsonl").read_bytes()
    original_errors = {path.name: path.read_bytes() for path in first.with_suffix(".errors").iterdir()}
    third = tmp_path / "turn-3.jsonl"
    failed_again, _ = operation(adapter_context, tmp_path, "auth", journal=third)
    assert failed_again["type"] == "turn_failed"
    assert first.with_suffix(".errors") != third.with_suffix(".errors")
    assert {path.name: path.read_bytes() for path in first.with_suffix(".errors").iterdir()} == original_errors
    assert {path.name: path.read_bytes() for path in third.with_suffix(".errors").iterdir()} == original_errors
    completed, _ = operation(adapter_context, tmp_path, "abstain", journal=second)
    assert not second.with_suffix(".errors").exists()
    assert failed["type"] == "turn_failed"
    assert completed["type"] == "turn_complete"
    assert first.read_bytes() == original_journal
    assert first.with_suffix(".pi.jsonl").read_bytes() == original_native
    sessions = [load_native_session(adapter_context[1], journal.with_suffix(".pi.jsonl"))
                for journal in (first, second)]
    assert sessions[0]["header"]["id"] != sessions[1]["header"]["id"]
    assert all(session["header"]["type"] == "session" for session in sessions)
    assert all(journal.with_suffix(".pi.jsonl").stat().st_mode & 0o777 == 0o600
               for journal in (first, second))


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
    preload.write_text(PRELOAD.replace("__MODE__", '"abstain"')
                       .replace("__STREAM_END__", '"pending"')
                       .replace("__REASONING_EFFORT__", "null")
                       .replace("  count++;", "  count++;" + barrier))
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
        assert not journal.with_suffix(".errors").exists()
    assert {path.name: path.read_bytes() for path in quota.iterdir()} == before


@pytest.mark.parametrize("mode,stream_end", [("truncated", "eof"), ("cancel", "pending"),
                                           ("missing-finish", "pending")])
def test_pi_unfinished_transport_remains_unsettled(adapter_context, tmp_path, mode, stream_end):
    result, _ = operation(adapter_context, tmp_path, mode, stream_end=stream_end)
    assert result["type"] == "turn_failed"
    assert result["request_count"] == 1
    assert result["remote_settled"] is False


def test_feedback_uses_original_session_and_separate_accounting(adapter_context, tmp_path):
    callbacks = []

    async def host_outcome(proposal):
        callbacks.append(proposal["final_text"])
        records = native_records(tmp_path / "turn.pi.jsonl")
        assert any("Offline transport fixture only." in json.dumps(record) for record in records)
        return 'Host review phase: final host result {"status":"unavailable"}. Return Markdown, no tools.'

    result, _ = operation(adapter_context, tmp_path, "tools", on_complete=host_outcome)
    assert len(callbacks) == 1
    assert result["type"] == "turn_complete" and result["request_count"] == 3
    assert result["usage"]["totalTokens"] == 54
    review = result["session_feedback"]
    assert review["type"] == "feedback_complete" and review["request_count"] == 1
    assert review["usage"]["totalTokens"] == 18 and review["tool_calls"] == 0
    assert review["final_text"].startswith("# Session review")
    records = native_records(tmp_path / "turn.pi.jsonl")
    serialized = json.dumps(records)
    assert "Host review phase:" in serialized and "# Session review" in serialized
    assert "Synthesis phase:" in serialized and "max_tool_calls" in serialized
    assert "get_patch_context" in serialized and "evaluate_predicate" in serialized
    assert len([record for record in records if record["type"] == "session"]) == 1


def test_nonfinal_round_releases_original_session_without_review(adapter_context, tmp_path):
    async def release(proposal):
        assert proposal["type"] == "turn_complete"
        return None

    result, _ = operation(adapter_context, tmp_path, "tools", on_complete=release)
    assert result["type"] == "turn_complete" and result["request_count"] == 3
    assert "session_feedback" not in result
    frames = [entry["frame"] for entry in native_records(tmp_path / "turn.jsonl")]
    assert frames[-1]["type"] == "feedback_complete" and frames[-1]["request_count"] == 0
    assert "Host review phase:" not in (tmp_path / "turn.pi.jsonl").read_text()


@pytest.mark.parametrize("mode", ["feedback-auth", "feedback-cancel", "feedback-tool"])
def test_feedback_failure_never_overwrites_proposal(adapter_context, tmp_path, mode):
    async def review(proposal):
        return 'Host review phase: final host result {"status":"not_rejected"}. No tools.'

    result, _ = operation(adapter_context, tmp_path, mode, on_complete=review)
    assert result["type"] == "turn_complete" and result["request_count"] == 3
    assert result["host_checked_predicates"] == ["rax <= 0"]
    assert result["session_feedback"]["type"] == "feedback_failed"
    frames = [entry["frame"] for entry in native_records(tmp_path / "turn.jsonl")]
    assert len([frame for frame in frames if frame["type"] == "tool_request"]) == 2


def test_feedback_deadline_is_fresh_after_host_work(adapter_context, tmp_path):
    async def review(proposal):
        return 'Host review phase: host outcome unavailable. Markdown only.'

    result, _ = operation(adapter_context, tmp_path, "feedback-deadline", on_complete=review)
    assert result["type"] == "turn_complete" and result["request_count"] == 3
    assert result["session_feedback"]["type"] == "feedback_failed"
    assert result["session_feedback"]["error_code"] == "timeout"
    assert result["session_feedback"]["request_count"] == 1


def test_host_cancellation_during_review_preserves_settled_proposal(adapter_context, tmp_path):
    async def review(proposal):
        task = asyncio.current_task()
        asyncio.get_running_loop().call_later(0.1, task.cancel)
        return 'Host review phase: host outcome not_rejected. Markdown only.'

    result, _ = operation(adapter_context, tmp_path, "feedback-timeout", on_complete=review)
    assert result["type"] == "turn_complete" and result["request_count"] == 3
    assert result["session_feedback"]["type"] == "feedback_failed"
    assert result["session_feedback"]["error_code"] == "cancelled"
    frames = [entry["frame"] for entry in native_records(tmp_path / "turn.jsonl")]
    assert any(frame["type"] == "cancel" for frame in frames)
    assert frames[-1]["type"] == "feedback_failed"


def test_callback_failure_cancels_and_disposes_live_session(adapter_context, tmp_path):
    async def failed_host(proposal):
        raise RuntimeError("offline host outcome failure")

    with pytest.raises(RuntimeError, match="offline host outcome failure"):
        operation(adapter_context, tmp_path, "tools", on_complete=failed_host)
    frames = [entry["frame"] for entry in native_records(tmp_path / "turn.jsonl")]
    assert any(frame["type"] == "cancel" for frame in frames)
    assert frames[-1]["type"] == "turn_failed" and frames[-1]["error_code"] == "cancelled"
    assert frames[-1]["remote_settled"] is True
