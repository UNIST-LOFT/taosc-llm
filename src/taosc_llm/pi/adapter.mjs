#!/usr/bin/env node
// One private, single-turn Pi worker. Stdout is exclusively the host JSONL protocol.
import { createReadStream } from 'node:fs';
import { readFile, realpath, stat } from 'node:fs/promises';
import { join, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';

const VERSION = 1;
const MAX_FRAME = 4 * 1024 * 1024;
const TOOL_NAMES = ['get_patch_context', 'get_function_analysis', 'list_cases', 'get_case', 'evaluate_predicate', 'test_candidate', 'get_candidate_result'];
const PROVIDER_ID = 'taosc-ollama-cloud';
const nativeFetch = globalThis.fetch.bind(globalThis);
const output = process.stdout.write.bind(process.stdout);
// Some SDK dependencies log diagnostics with payload-bearing exception messages.
for (const method of ['log', 'info', 'warn', 'error', 'debug', 'trace']) console[method] = () => {};

class SafeError extends Error {
  constructor(code) { super(code); this.code = code; }
}
function insist(value, code = 'protocol_error') { if (!value) throw new SafeError(code); }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function text(value) { return typeof value === 'string' && value.length > 0; }
function exactKeys(value, allowed, required = allowed) {
  insist(object(value) && Object.keys(value).every(k => allowed.includes(k)) && required.every(k => Object.hasOwn(value, k)));
}
function positive(value) { return Number.isSafeInteger(value) && value > 0; }
function emit(frame) {
  const line = JSON.stringify({ protocol_version: VERSION, run_id: start.run_id, ...frame });
  insist(Buffer.byteLength(line) <= MAX_FRAME, 'resource_limit');
  output(line + '\n');
}

let start;
let session;
let runtime;
let unsubscribe;
let finished = false;
let failure;
let settledEvent = false;
let finalAssistant;
let toolCalls = 0;
let modelTurns = 0;
let serial = 0;
let timer;
let inputBuffer = Buffer.alloc(0);
const pending = new Map();
const usedIds = new Set();
const requests = [];
let httpStatus = null;
let retryAfter = null;
let chatEndpoint;
const aborter = new AbortController();

function remoteSettled() { return requests.every(r => r.complete) && requests.every(r => !r.active); }
function rejectTools() {
  for (const { reject, clean } of pending.values()) { clean(); reject(new SafeError('cancelled')); }
  pending.clear();
}
function stop(code) {
  if (finished || failure) return;
  failure = code;
  aborter.abort();
  rejectTools();
  // Do not await from an event callback: prompt() owns cleanup and terminal output.
  if (session) void session.abort().catch(() => {});
}

function parseArgs(argv) {
  const options = {};
  insist(argv.length === 4, 'configuration_error');
  for (let i = 0; i < argv.length; i += 2) {
    insist(['--sdk-root', '--credential-fd'].includes(argv[i]) && !Object.hasOwn(options, argv[i]), 'configuration_error');
    options[argv[i]] = argv[i + 1];
  }
  insist(isAbsolute(options['--sdk-root'] ?? '') && /^\d+$/.test(options['--credential-fd'] ?? ''), 'configuration_error');
  const fd = Number(options['--credential-fd']);
  insist(Number.isSafeInteger(fd) && fd >= 3, 'configuration_error');
  return { sdkRoot: options['--sdk-root'], fd };
}
async function credentials(fd) {
  const chunks = [];
  let length = 0;
  for await (const chunk of createReadStream('', { fd, autoClose: true, signal: aborter.signal })) {
    length += chunk.length;
    insist(length <= 65536, 'credential_error');
    chunks.push(chunk);
  }
  const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
  exactKeys(data, ['api_key']);
  insist(text(data.api_key) && !/[\r\n\0]/.test(data.api_key), 'credential_error');
  return data.api_key;
}
async function loadSdk(root) {
  const imports = {};
  for (const name of ['@earendil-works/pi-coding-agent', '@earendil-works/pi-ai']) {
    const packagePath = join(root, 'node_modules', name, 'package.json');
    const metadata = JSON.parse(await readFile(packagePath, 'utf8'));
    insist(metadata.name === name && metadata.version === '1.4.0', 'sdk_version_mismatch');
    // These packages expose import-only ESM conditions; require.resolve rejects them.
    const packageRoot = await realpath(join(root, 'node_modules', name));
    const declaredEntry = metadata.exports?.['.']?.import;
    insist(typeof declaredEntry === 'string', 'sdk_configuration_error');
    const entry = await realpath(join(packageRoot, declaredEntry));
    insist(entry.startsWith(packageRoot + '/'), 'sdk_configuration_error');
    imports[name] = await import(pathToFileURL(entry).href);
  }
  const aiRoot = await realpath(join(root, 'node_modules/@earendil-works/pi-ai'));
  const streamEntry = await realpath(join(aiRoot, 'dist/api/openai-completions.js'));
  insist(streamEntry.startsWith(aiRoot + '/'), 'sdk_configuration_error');
  return { sdk: imports['@earendil-works/pi-coding-agent'], ai: imports['@earendil-works/pi-ai'], chat: await import(pathToFileURL(streamEntry).href) };
}

// Strict validation is deliberately small: the host's five schemas use this subset.
// Unsupported schema vocabulary fails closed rather than silently weakening checks.
function schemaSupported(schema, depth = 0) {
  insist(object(schema) && depth < 16, 'invalid_tool_schema');
  const keys = ['type', 'properties', 'required', 'additionalProperties', 'enum', 'const', 'items', 'minLength', 'maxLength', 'minItems', 'maxItems', 'description', 'title', 'minimum', 'maximum'];
  insist(Object.keys(schema).every(k => keys.includes(k)), 'invalid_tool_schema');
  insist(['object', 'string', 'array', 'integer', 'number', 'boolean', 'null'].includes(schema.type), 'invalid_tool_schema');
  if (schema.type === 'object') {
    insist(schema.additionalProperties === false && object(schema.properties), 'invalid_tool_schema');
    insist(schema.required === undefined || (Array.isArray(schema.required) && schema.required.every(k => Object.hasOwn(schema.properties, k))), 'invalid_tool_schema');
    for (const sub of Object.values(schema.properties)) schemaSupported(sub, depth + 1);
  }
  if (schema.type === 'array') schemaSupported(schema.items, depth + 1);
}
function conforms(value, schema) {
  if (schema.const !== undefined && value !== schema.const) return false;
  if (schema.enum && !schema.enum.includes(value)) return false;
  switch (schema.type) {
    case 'object': return object(value) && Object.keys(value).every(k => Object.hasOwn(schema.properties, k)) && (schema.required ?? []).every(k => Object.hasOwn(value, k)) && Object.entries(value).every(([k, v]) => conforms(v, schema.properties[k]));
    case 'string': return typeof value === 'string' && value.length >= (schema.minLength ?? 0) && value.length <= (schema.maxLength ?? Infinity);
    case 'array': return Array.isArray(value) && value.length >= (schema.minItems ?? 0) && value.length <= (schema.maxItems ?? Infinity) && value.every(v => conforms(v, schema.items));
    case 'integer': return Number.isSafeInteger(value) && value >= (schema.minimum ?? -Infinity) && value <= (schema.maximum ?? Infinity);
    case 'number': return typeof value === 'number' && Number.isFinite(value) && value >= (schema.minimum ?? -Infinity) && value <= (schema.maximum ?? Infinity);
    case 'boolean': return typeof value === 'boolean';
    case 'null': return value === null;
    default: return false;
  }
}
function validateStart(frame) {
  exactKeys(frame, ['protocol_version', 'run_id', 'request_id', 'type', 'provider', 'system_prompt', 'user_prompt', 'context_id', 'tools', 'private_dir']);
  insist(frame.protocol_version === VERSION && frame.type === 'start_turn' && [frame.run_id, frame.request_id, frame.context_id].every(text));
  insist(typeof frame.system_prompt === 'string' && typeof frame.user_prompt === 'string' && isAbsolute(frame.private_dir));
  const p = frame.provider;
  exactKeys(p, ['base_url', 'model', 'max_in_flight', 'workers', 'context_window', 'max_tokens', 'timeout_seconds', 'max_turns', 'max_tool_calls']);
  insist(text(p.base_url) && !/[\x00-\x20\x7f]/.test(p.base_url) && text(p.model), 'configuration_error');
  let base;
  try { base = new URL(p.base_url); } catch { throw new SafeError('configuration_error'); }
  insist(base.protocol === 'https:' && base.hostname && !base.username && !base.password && !base.search && !base.hash, 'configuration_error');
  insist(Number.isSafeInteger(p.max_in_flight) && p.max_in_flight >= 0 && positive(p.workers), 'configuration_error');
  const hostname = base.hostname.replace(/\.$/, '');
  if (hostname === 'ollama.com' || hostname.endsWith('.ollama.com')) {
    insist(p.base_url === 'https://ollama.com/v1' && p.model === 'deepseek-v4.1-flash:1017' && p.max_in_flight >= 1 && p.max_in_flight <= 3, 'configuration_error');
  }
  chatEndpoint = new URL(base.href.replace(/\/$/, '') + '/chat/completions').href;
  insist([p.context_window, p.max_tokens, p.max_turns, p.max_tool_calls].every(positive) && Number.isFinite(p.timeout_seconds) && p.timeout_seconds > 0 && p.timeout_seconds * 1000 <= 2147483647, 'configuration_error');
  insist(Array.isArray(frame.tools) && frame.tools.length === TOOL_NAMES.length, 'invalid_tool_schema');
  insist(new Set(frame.tools.map(t => t.name)).size === TOOL_NAMES.length && frame.tools.every(t => TOOL_NAMES.includes(t.name)), 'invalid_tool_schema');
  for (const tool of frame.tools) {
    exactKeys(tool, ['name', 'description', 'parameters']);
    insist(text(tool.description), 'invalid_tool_schema');
    schemaSupported(tool.parameters);
    insist(tool.parameters.type === 'object' && tool.parameters.required?.includes('context_id'), 'invalid_tool_schema');
  }
}

function retryDelay(value) {
  if (value === null) return null;
  if (/^\d+(\.\d+)?$/.test(value)) { const n = Number(value); return Number.isFinite(n) ? n : null; }
  const time = Date.parse(value);
  return Number.isFinite(time) ? Math.max(0, (time - Date.now()) / 1000) : null;
}
async function guardedFetch(input, init) {
  const url = new URL(input instanceof Request ? input.url : input);
  insist(chatEndpoint && url.href === chatEndpoint && (init?.method ?? (input instanceof Request ? input.method : 'GET')) === 'POST', 'transport_rejected');
  insist(!failure && !requests.some(r => r.active || !r.complete), 'transport_rejected');
  const record = { active: true, complete: false, usage: null };
  requests.push(record);
  let response;
  try {
    const signal = init?.signal ? AbortSignal.any([init.signal, aborter.signal]) : aborter.signal;
    response = await nativeFetch(input, { ...init, redirect: 'manual', signal });
  } catch { record.active = false; throw new SafeError('provider_transport_error'); }
  httpStatus = response.status;
  retryAfter = response.status === 429 ? retryDelay(response.headers.get('retry-after')) : null;
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel().catch(() => {});
    record.active = false;
    // Redirect response is terminal; no credentials ever reach the redirect location.
    record.complete = true;
    throw new SafeError('provider_redirect_rejected');
  }
  if (!response.body) { record.active = false; record.complete = !response.ok; throw new SafeError('provider_transport_error'); }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let doneMarker = false;
  let finishReason = false;
  const inspect = bytes => {
    if (!response.ok) return;
    buffer += decoder.decode(bytes, { stream: true });
    insist(buffer.length <= MAX_FRAME, 'resource_limit');
    let split;
    while ((split = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, split).trimEnd();
      buffer = buffer.slice(split + 1);
      if (!line.startsWith('data:')) continue;
      const data = line.slice(5).trim();
      if (data === '[DONE]') doneMarker = true;
      else if (data) {
        try {
          const event = JSON.parse(data);
          if (event.choices?.some(c => typeof c.finish_reason === 'string' && c.finish_reason.length)) finishReason = true;
          const u = event.usage;
          if (u && ['prompt_tokens', 'completion_tokens', 'total_tokens'].every(k => Number.isSafeInteger(u[k]) && u[k] >= 0)) {
            record.usage = { input: u.prompt_tokens, output: u.completion_tokens, totalTokens: u.total_tokens };
          }
        } catch { /* Provider parser owns malformed-event handling. */ }
      }
    }
  };
  const body = new ReadableStream({
    async pull(controller) {
      try {
        const { value, done } = await reader.read();
        if (done) {
          record.active = false;
          record.complete = !response.ok || (doneMarker && finishReason);
          reader.releaseLock();
          controller.close();
        } else { inspect(value); controller.enqueue(value); }
      } catch {
        record.active = false;
        try { await reader.cancel(); } catch {}
        controller.error(new SafeError('provider_transport_error'));
      }
    },
    async cancel() {
      // A consumer may cancel immediately after [DONE], before requesting EOF.
      record.complete = !response.ok || (doneMarker && finishReason);
      try { await reader.cancel(); } finally { record.active = false; }
    },
  });
  return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
}

function toolBridge(tool) {
  return {
    ...tool, label: tool.name, executionMode: 'sequential',
    async execute(_id, args, signal) {
      if (failure || signal?.aborted) throw new SafeError('cancelled');
      if (++toolCalls > start.provider.max_tool_calls) { stop('resource_limit'); throw new SafeError('resource_limit'); }
      if (!conforms(args, tool.parameters) || args.context_id !== start.context_id) {
        return { content: [{ type: 'text', text: JSON.stringify({ error_code: 'invalid_arguments' }) }], details: {} };
      }
      let requestId;
      do { requestId = `tool-${++serial}`; } while (usedIds.has(requestId));
      usedIds.add(requestId);
      const result = await new Promise((resolveResult, reject) => {
        const onAbort = () => { pending.delete(requestId); reject(new SafeError('cancelled')); };
        const clean = () => signal?.removeEventListener('abort', onAbort);
        pending.set(requestId, { resolve: resolveResult, reject, clean });
        signal?.addEventListener('abort', onAbort, { once: true });
        emit({ type: 'tool_request', request_id: requestId, context_id: start.context_id, tool: tool.name, arguments: args });
      });
      return { content: [{ type: 'text', text: JSON.stringify(result) }], details: {} };
    },
  };
}
function emptyLoader(sdk) {
  const extensions = { extensions: [], errors: [], runtime: sdk.createExtensionRuntime() };
  return {
    getExtensions: () => extensions,
    getSkills: () => ({ skills: [], diagnostics: [] }),
    getPrompts: () => ({ prompts: [], diagnostics: [] }),
    getThemes: () => ({ themes: [], diagnostics: [] }),
    getAgentsFiles: () => ({ agentsFiles: [] }),
    getSystemPrompt: () => start.system_prompt,
    getSystemPromptSource: () => undefined,
    getAppendSystemPrompt: () => [],
    getAppendSystemPromptSources: () => [],
    extendResources() {}, async reload() {},
  };
}
function reportedUsage() {
  if (!requests.length || requests.some(r => r.usage === null)) return null;
  const result = { scope: 'all_requests', input: 0, output: 0, totalTokens: 0 };
  for (const request of requests) {
    for (const key of ['input', 'output', 'totalTokens']) result[key] += request.usage[key];
  }
  return ['input', 'output', 'totalTokens'].every(k => Number.isSafeInteger(result[k])) ? result : null;
}
async function run(frame, options, keyPromise) {
  let completion;
  try {
    validateStart(frame);
    usedIds.add(frame.request_id);
    timer = setTimeout(() => stop('timeout'), frame.provider.timeout_seconds * 1000);
    const privateInfo = await stat(frame.private_dir);
    insist(privateInfo.isDirectory() && (privateInfo.mode & 0o077) === 0, 'isolation_error');
    const { sdk, ai, chat } = await loadSdk(options.sdkRoot);
    const key = await keyPromise;
    insist(!failure, failure);
    runtime = await sdk.ModelRuntime.create({ credentials: new ai.InMemoryCredentialStore(), modelsPath: null, allowModelNetwork: false, refreshOnCreate: false });
    const p = frame.provider;
    runtime.registerProvider(PROVIDER_ID, {
      baseUrl: p.base_url, api: 'openai-completions', authHeader: true,
      models: [{ id: p.model, name: p.model, input: ['text'], reasoning: false,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: p.context_window, maxTokens: p.max_tokens,
        compat: { supportsStore: false, supportsDeveloperRole: false, supportsReasoningEffort: false, supportsUsageInStreaming: true, maxTokensField: 'max_tokens' } }],
      streamSimple(model, context, opts) {
        if (failure) throw new SafeError(failure);
        if (++modelTurns > p.max_turns) { stop('resource_limit'); throw new SafeError('resource_limit'); }
        insist(model.provider === PROVIDER_ID && model.id === p.model && model.baseUrl === p.base_url, 'model_mismatch');
        return chat.streamSimple(model, context, { ...opts, env: {}, fetch: guardedFetch, maxTokens: p.max_tokens, maxRetries: 0,
          timeoutMs: p.timeout_seconds * 1000, cacheRetention: 'none', reasoning: undefined,
          onPayload(payload) {
            // No forced tool_choice, provider-specific thinking knobs, or hidden cache warming.
            delete payload.tool_choice;
            delete payload.reasoning_effort;
            return payload;
          } });
      },
    });
    await runtime.setRuntimeApiKey(PROVIDER_ID, key);
    const model = runtime.getModel(PROVIDER_ID, p.model);
    insist(model && model.provider === PROVIDER_ID && model.id === p.model && model.baseUrl === p.base_url, 'model_mismatch');
    const result = await sdk.createAgentSession({
      cwd: frame.private_dir, agentDir: frame.private_dir, modelRuntime: runtime, model, thinkingLevel: 'off',
      scopedModels: [{ model, thinkingLevel: 'off' }], noTools: 'builtin', tools: TOOL_NAMES,
      customTools: frame.tools.map(toolBridge), resourceLoader: emptyLoader(sdk),
      sessionManager: sdk.SessionManager.inMemory(frame.private_dir),
      settingsManager: sdk.SettingsManager.inMemory({ cacheWarming: 'off', compaction: { enabled: false }, retry: { enabled: false, maxRetries: 0, provider: { maxRetries: 0 } } }),
    });
    session = result.session;
    const active = session.getActiveToolNames();
    insist(active.length === TOOL_NAMES.length && TOOL_NAMES.every(name => active.includes(name)), 'tool_isolation_error');
    unsubscribe = session.subscribe(event => {
      if (event.type === 'agent_settled') settledEvent = !event.aborted;
      if (event.type === 'message_end' && event.message.role === 'assistant') finalAssistant = event.message;
    });
    if (failure) throw new SafeError(failure);
    await session.prompt(frame.user_prompt);
    await session.waitForIdle();
    insist(!failure, failure);
    insist(settledEvent && remoteSettled() && requests.length > 0, 'provider_unsettled');
    if (!finalAssistant || finalAssistant.stopReason !== 'stop') {
      const code = finalAssistant?.stopReason === 'length' ? 'output_limit'
        : httpStatus >= 300 && httpStatus < 400 ? 'provider_redirect_rejected'
        : httpStatus === 429 ? 'provider_rate_limited'
        : httpStatus === 401 || httpStatus === 403 ? 'provider_authentication_failed'
        : httpStatus === 400 || httpStatus === 404 || httpStatus === 422 ? 'provider_capability_rejected'
        : 'provider_error';
      throw new SafeError(code);
    }
    const finalText = finalAssistant.content.filter(c => c.type === 'text').map(c => c.text).join('');
    insist(text(finalText), 'empty_response');
    completion = { type: 'turn_complete', final_text: finalText, remote_settled: true, tool_calls: toolCalls, model_turns: modelTurns, usage: reportedUsage(), request_count: requests.length, active_tools: active,
      provider_metadata: { provider: PROVIDER_ID, base_url: p.base_url, model: p.model, api: 'openai-completions', sdk_version: '1.4.0', node_version: process.versions.node, pricing: 'unknown', context_window: p.context_window, max_tokens: p.max_tokens, bounds_source: 'client_configuration', capability_admission: 'unverified' } };
  } catch (error) {
    failure ??= error instanceof SafeError ? error.code : 'adapter_error';
  } finally {
    clearTimeout(timer);
    if (failure) { aborter.abort(); rejectTools(); }
    if (session) {
      try { if (failure) await session.abort(); await session.waitForIdle(); } catch { failure ??= 'cleanup_error'; }
      unsubscribe?.();
      try { session.dispose(); } catch { failure ??= 'cleanup_error'; }
    }
    if (runtime) { try { await runtime.removeRuntimeApiKey(PROVIDER_ID); } catch { failure ??= 'cleanup_error'; } }
    finished = true;
    const terminal = failure ? { type: 'turn_failed', error_code: failure, remote_settled: remoteSettled(), retry_after_seconds: retryAfter, http_status: httpStatus, request_count: requests.length } : completion;
    try { emit({ request_id: frame.request_id, ...terminal }); }
    catch { emit({ request_id: frame.request_id, type: 'turn_failed', error_code: 'resource_limit', remote_settled: remoteSettled(), retry_after_seconds: null, http_status: httpStatus, request_count: requests.length }); }
    process.stdin.destroy();
    // No lingering SDK telemetry/background handles may extend the credential worker lifetime.
    process.exitCode = failure ? 1 : 0;
    process.stdout.end(() => process.exit(process.exitCode));
  }
}

function receive(frame, options, keyPromise) {
  insist(!finished && object(frame) && frame.protocol_version === VERSION && text(frame.run_id) && text(frame.request_id));
  if (!start) {
    start = frame;
    void run(frame, options, keyPromise);
    return;
  }
  insist(frame.run_id === start.run_id);
  if (frame.type === 'cancel') {
    exactKeys(frame, ['protocol_version', 'run_id', 'request_id', 'type']);
    insist(!usedIds.has(frame.request_id));
    usedIds.add(frame.request_id);
    stop('cancelled');
  } else {
    exactKeys(frame, ['protocol_version', 'run_id', 'request_id', 'type', 'result']);
    insist(!failure && frame.type === 'tool_result' && object(frame.result));
    const waiter = pending.get(frame.request_id);
    insist(waiter);
    pending.delete(frame.request_id);
    waiter.clean();
    waiter.resolve(frame.result);
  }
}
async function main() {
  const [major, minor] = process.versions.node.split('.').map(Number);
  insist(major > 22 || (major === 22 && minor >= 19), 'node_version_mismatch');
  const options = parseArgs(process.argv.slice(2));
  globalThis.fetch = guardedFetch;
  const keyPromise = credentials(options.fd);
  // Attach immediately so a malformed closed pipe cannot become an unhandled rejection.
  keyPromise.catch(() => { stop('credential_error'); });
  process.stdin.on('data', chunk => {
    if (finished) return;
    try {
      inputBuffer = Buffer.concat([inputBuffer, chunk]);
      let newline;
      while ((newline = inputBuffer.indexOf(10)) >= 0) {
        insist(newline <= MAX_FRAME, 'resource_limit');
        const line = inputBuffer.subarray(0, newline);
        inputBuffer = inputBuffer.subarray(newline + 1);
        insist(line.length > 0);
        const frame = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line));
        receive(frame, options, keyPromise);
      }
      insist(inputBuffer.length <= MAX_FRAME, 'resource_limit');
    } catch { if (start) stop('protocol_error'); else process.exit(1); }
  });
  process.stdin.on('end', () => { if (!finished) { if (start) stop('host_disconnected'); else process.exit(1); } });
  process.stdin.on('error', () => stop('host_disconnected'));
  process.stdout.on('error', () => { stop('host_disconnected'); process.exitCode = 1; });
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { if (start) stop('cancelled'); else process.exit(1); });
}
main().catch(() => { process.stderr.write('taosc Pi adapter: initialization failed\n'); process.exit(1); });
