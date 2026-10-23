'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(
  path.join(__dirname, '../../frontend/js/api.js'),
  'utf8'
);

function createApi(fetchImpl) {
  const window = {
    AbortController,
    URL,
    console,
    fetch: fetchImpl,
    location: {
      origin: 'http://localhost:8081',
      protocol: 'http:'
    }
  };

  vm.runInNewContext(source, {
    AbortController,
    URL,
    clearTimeout,
    console,
    setTimeout,
    window
  });

  return window.CanaryAPI;
}

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body)
  };
}

test('configured API routes use same-origin /api paths and leave Member B endpoints disabled', () => {
  const api = createApi(async () => response({ status: 'ok' }));
  const config = api.getConfig();

  assert.equal(config.apiBaseUrl, '');
  assert.equal(config.endpoints.health.path, '/api/health');
  assert.equal(config.endpoints.attack.path, '/api/attack');
  assert.equal(config.endpoints.defense.path, '/api/defense');
  assert.equal(config.endpoints.result.path, '/api/result');
  assert.equal(config.endpoints.audit, null);
  assert.equal(config.endpoints.canary, null);
  assert.equal(config.endpoints.verify, null);
});

test('attack and defense send the backend prompt contract', async () => {
  const requests = [];
  const api = createApi(async (url, init) => {
    requests.push({ url: String(url), init });
    const operation = String(url).endsWith('/attack') ? 'attack' : 'defense';
    return response({ operation, result: 'stub result' });
  });

  const attack = await api.attack({ prompt: 'attack prompt' });
  const defense = await api.defense({ prompt: 'defense prompt' });

  assert.equal(requests.length, 2);
  assert.equal(requests[0].url, 'http://localhost:8081/api/attack');
  assert.equal(requests[0].init.method, 'POST');
  assert.equal(requests[0].init.headers['Content-Type'], 'application/json');
  assert.equal(requests[0].init.body, '{"prompt":"attack prompt"}');
  assert.equal(requests[1].url, 'http://localhost:8081/api/defense');
  assert.equal(requests[1].init.body, '{"prompt":"defense prompt"}');
  assert.equal(JSON.stringify(attack.data), '{"operation":"attack","result":"stub result"}');
  assert.equal(JSON.stringify(defense.data), '{"operation":"defense","result":"stub result"}');
});

test('latest result uses the backend result wrapper', async () => {
  const requests = [];
  const api = createApi(async (url, init) => {
    requests.push({ url: String(url), init });
    return response({ result: { operation: 'query', result: 'latest' } });
  });

  const result = await api.result();

  assert.equal(requests[0].url, 'http://localhost:8081/api/result');
  assert.equal(requests[0].init.method, 'GET');
  assert.equal(JSON.stringify(result.data), '{"result":{"operation":"query","result":"latest"}}');
});

test('audit, canary, and verification return unavailable without making requests', async () => {
  let requestCount = 0;
  const api = createApi(async () => {
    requestCount += 1;
    return response({});
  });

  for (const result of await Promise.all([api.audit(), api.canary(), api.verify()])) {
    assert.equal(result.ok, false);
    assert.equal(result.kind, 'not_configured');
  }
  assert.equal(requestCount, 0);
});

test('security endpoints can be configured when the real pipeline is added', () => {
  const api = createApi(async () => response({}));

  const configured = api.configure({
    endpoints: { audit: { method: 'GET', path: '/api/audit' } }
  });
  assert.equal(configured.ok, true);
  assert.equal(configured.problems.length, 0);
  assert.equal(api.getConfig().endpoints.audit.path, '/api/audit');
});
