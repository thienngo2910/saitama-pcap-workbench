import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/index.mjs';

const ORIGIN = 'https://thienngo2910.github.io';
const ENV = {
  TURNSTILE_SECRET: 'test-turnstile-secret',
  OPENAI_API_KEY: 'test-openai-key',
  AI_RATE_LIMITER: { limit: async () => ({ success: true }) },
};
const summary = {
  filename: 'sample.pcap', sha256: 'a'.repeat(64), packet_count: 1, bytes: 24,
  overview: { protocols: [{ name: 'TCP', packets: 1 }] },
  sensitive_value_count: 1,
  sensitive_references: [{ type: 'credential-like', confidence: 'medium', packets: [1], value: 'DO_NOT_SEND_THIS_SECRET' }],
  caseNotes: 'DO_NOT_SEND_CASE_NOTES',
};

function capture(magic = [0xd4, 0xc3, 0xb2, 0xa1]) {
  const bytes = new Uint8Array(24);
  bytes.set(magic);
  return new File([bytes], 'sample.pcap', { type: 'application/vnd.tcpdump.pcap' });
}
function request(file) {
  const form = new FormData();
  form.set('pcap', file);
  form.set('summary', JSON.stringify(summary));
  form.set('cf-turnstile-response', 'valid-turnstile-token');
  return new Request('https://worker.example/analyze', {
    method: 'POST', headers: { Origin: ORIGIN }, body: form,
  });
}

test('verifies Turnstile before forwarding any data', async t => {
  const oldFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async url => {
    calls++;
    assert.match(String(url), /siteverify/);
    return Response.json({ success: false });
  };
  t.after(() => { globalThis.fetch = oldFetch; });
  const response = await worker.fetch(request(capture()), ENV);
  assert.equal(response.status, 403);
  assert.equal(calls, 1);
});

test('rejects over-limit clients before upstream requests', async t => {
  const oldFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls++; throw new Error('must not call upstream'); };
  t.after(() => { globalThis.fetch = oldFetch; });
  const limited = { ...ENV, AI_RATE_LIMITER: { limit: async () => ({ success: false }) } };
  const response = await worker.fetch(request(capture()), limited);
  assert.equal(response.status, 429);
  assert.equal(calls, 0);
});

test('forwards the original PCAP only after Turnstile verification, omits secret summary values and cleans temporary files', async t => {
  const oldFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    if (String(url).endsWith('/siteverify')) {
      const values = new URLSearchParams(init.body);
      assert.equal(values.get('secret'), ENV.TURNSTILE_SECRET);
      assert.equal(values.get('response'), 'valid-turnstile-token');
      return Response.json({ success: true, action: 'analyze-pcap', hostname: 'thienngo2910.github.io' });
    }
    if (String(url).endsWith('/v1/files')) {
      const uploaded = init.body.get('file');
      assert.equal(uploaded.name, 'sample.pcap');
      assert.deepEqual([...new Uint8Array(await uploaded.arrayBuffer())], [...new Uint8Array(await capture().arrayBuffer())]);
      return Response.json({ id: 'file_test123' });
    }
    if (String(url).endsWith('/v1/responses')) {
      const payload = JSON.parse(init.body);
      assert.equal(payload.store, false);
      assert.deepEqual(payload.tools[0].container.file_ids, ['file_test123']);
      assert.equal(payload.tools[0].type, 'code_interpreter');
      assert.equal(payload.input.includes('DO_NOT_SEND_THIS_SECRET'), false);
      assert.equal(payload.input.includes('DO_NOT_SEND_CASE_NOTES'), false);
      return Response.json({ output: [
        { type: 'code_interpreter_call', container_id: 'cntr_test123' },
        { type: 'message', content: [{ type: 'output_text', text: 'Tổng quan; bằng chứng frame 1.' }] },
      ] });
    }
    if (init.method === 'DELETE') return new Response(null, { status: 204 });
    throw new Error('unexpected upstream request: ' + url);
  };
  t.after(() => { globalThis.fetch = oldFetch; });
  const response = await worker.fetch(request(capture()), ENV);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.uploaded_file, true);
  assert.match(body.analysis, /frame 1/);
  assert.deepEqual(calls.map(call => String(call.url).endsWith('/siteverify') ? 'verify' : (call.init.method || 'POST')), ['verify', 'POST', 'POST', 'DELETE', 'DELETE']);
});

test('rejects a failed signature before siteverify or OpenAI', async t => {
  const oldFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls++; throw new Error('must not call upstream'); };
  t.after(() => { globalThis.fetch = oldFetch; });
  const response = await worker.fetch(request(capture([0, 1, 2, 3])), ENV);
  assert.equal(response.status, 400);
  assert.equal(calls, 0);
});
