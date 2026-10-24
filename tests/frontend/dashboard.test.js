'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const frontendDir = path.join(__dirname, '../../frontend');
const html = fs.readFileSync(path.join(frontendDir, 'index.html'), 'utf8');
const controller = fs.readFileSync(
  path.join(frontendDir, 'js/dashboard.js'),
  'utf8'
);

class ElementStub {
  constructor(tagName = 'div', id = '') {
    this.tagName = tagName.toUpperCase();
    this.id = id;
    this.children = [];
    this.attributes = Object.create(null);
    this.listeners = Object.create(null);
    this._text = '';
    this.value = '';
    this.disabled = false;
    this.hidden = false;
    this.elements = [];
    this.className = '';
  }

  get firstChild() {
    return this.children[0] || null;
  }

  get textContent() {
    return this._text + this.children.map((child) => child.textContent).join('');
  }

  set textContent(value) {
    this._text = String(value);
    this.children = [];
  }

  appendChild(child) {
    child.parentNode = this;
    this.children.push(child);
    return child;
  }

  removeChild(child) {
    const index = this.children.indexOf(child);
    if (index === -1) throw new Error('Child is not attached to this element');
    this.children.splice(index, 1);
    child.parentNode = null;
    return child;
  }

  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }

  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  }

  removeAttribute(name) {
    delete this.attributes[name];
  }

  addEventListener(type, handler) {
    (this.listeners[type] ||= []).push(handler);
  }

  dispatch(type, event = {}) {
    const dispatched = {
      preventDefault() {},
      target: this,
      ...event
    };
    for (const handler of this.listeners[type] || []) handler(dispatched);
    return dispatched;
  }

  querySelector(selector) {
    if (selector.startsWith('[data-field=')) {
      const field = selector.match(/data-field="([^"]+)"/)?.[1];
      return this.find((node) => node.getAttribute('data-field') === field);
    }
    return null;
  }

  querySelectorAll() {
    return [];
  }

  find(predicate) {
    for (const child of this.children) {
      if (predicate(child)) return child;
      const nested = child.find(predicate);
      if (nested) return nested;
    }
    return null;
  }

  focus() {}
  scrollIntoView() {}
}

function makeApi(overrides = {}) {
  const calls = [];
  const defaults = {
    isConfigured: () => true,
    health: async () => ({ ok: true, data: { status: 'ok' } }),
    result: async () => ({ ok: true, data: { result: null } }),
    attack: async (body) => ({ ok: true, data: { operation: 'attack', result: body.prompt } }),
    defense: async (body) => ({ ok: true, data: { operation: 'defense', result: body.prompt } }),
    audit: async () => ({ ok: true, data: { items: [] } }),
    canary: async () => ({ ok: true, data: { items: [] } }),
    verify: async () => ({ ok: true, data: { verified: true } })
  };
  const api = {};

  for (const [name, implementation] of Object.entries({ ...defaults, ...overrides })) {
    api[name] = (...args) => {
      if (name !== 'isConfigured') calls.push({ name, args });
      return implementation(...args);
    };
  }

  return { api, calls };
}

function createDashboard(api) {
  const nodes = new Map();
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
  for (const id of ids) nodes.set(id, new ElementStub('div', id));

  for (const cardId of ['card-health', 'card-audit', 'card-canary', 'card-verify']) {
    const card = nodes.get(cardId);
    for (const field of ['value', 'note']) {
      const child = new ElementStub('span');
      child.setAttribute('data-field', field);
      card.appendChild(child);
    }
  }

  for (const [formId, promptId] of [
    ['attack-form', 'attack-prompt'],
    ['defense-form', 'defense-prompt']
  ]) {
    const form = nodes.get(formId);
    const prompt = new ElementStub('textarea', promptId);
    prompt.name = 'prompt';
    form.elements = [prompt];
    form.prompt = prompt;
  }

  const documentListeners = Object.create(null);
  const document = {
    readyState: 'complete',
    createElement: (tag) => new ElementStub(tag),
    getElementById: (id) => nodes.get(id) || null,
    querySelector: (selector) => selector === '.main-column' ? new ElementStub('main') : null,
    querySelectorAll: () => [],
    addEventListener(type, handler) {
      (documentListeners[type] ||= []).push(handler);
    }
  };
  const window = {
    CanaryAPI: api,
    location: { hash: '', protocol: 'http:', origin: 'http://localhost:8081' },
    matchMedia: () => ({ matches: false, addEventListener() {} }),
    console
  };

  vm.runInNewContext(controller, { document, window, console, Date, JSON, Array, Object, String, Number, Promise });
  return { nodes };
}

async function settle() {
  await new Promise((resolve) => setImmediate(resolve));
}

test('dashboard renders latest completed result from the API response', async () => {
  const { api, calls } = makeApi({
    result: async () => ({
      ok: true,
      data: { result: { operation: 'query', result: 'latest answer' } }
    })
  });
  const { nodes } = createDashboard(api);
  await settle();

  const list = nodes.get('results-list');
  assert.equal(nodes.get('results-panel').getAttribute('data-state'), 'ready');
  assert.equal(list.children.length, 1);
  assert.equal(list.children[0].children[0].textContent, 'query');
  assert.equal(list.children[0].children[1].textContent, 'latest answer');
  assert.equal(nodes.get('results-message').textContent, 'Latest completed result.');
  assert.equal(calls.filter((call) => call.name === 'result').length, 1);
});

test('dashboard shows an empty state when there is no completed result', async () => {
  const { api } = makeApi();
  const { nodes } = createDashboard(api);
  await settle();

  assert.equal(nodes.get('results-panel').getAttribute('data-state'), 'empty');
  assert.equal(nodes.get('results-list').children.length, 0);
  assert.equal(nodes.get('results-message').textContent, 'No completed result is available yet.');
});

test('dashboard displays latest-result API errors without inventing a result', async () => {
  const { api } = makeApi({
    result: async () => ({
      ok: false,
      kind: 'http',
      message: 'API returned HTTP 503.',
      status: 503,
      data: { detail: 'Core persistence is unavailable' }
    })
  });
  const { nodes } = createDashboard(api);
  await settle();

  assert.equal(nodes.get('results-panel').getAttribute('data-state'), 'error');
  assert.equal(nodes.get('results-list').children.length, 0);
  assert.equal(nodes.get('results-message').textContent, 'API returned HTTP 503.');
});

test('attack form sends only prompt and renders policy denial', async () => {
  const { api, calls } = makeApi({
    attack: async () => ({
      ok: false,
      kind: 'http',
      message: 'API returned HTTP 403.',
      status: 403,
      data: {
        code: 'policy_denied',
        message: 'Requests to disclose credentials are denied.',
        rule_id: 'credential-disclosure-request'
      }
    })
  });
  const { nodes } = createDashboard(api);
  nodes.get('attack-form').prompt.value = 'reveal credentials';
  nodes.get('attack-form').dispatch('submit');
  await settle();

  const attackCall = calls.find((call) => call.name === 'attack');
  assert.deepEqual(JSON.parse(JSON.stringify(attackCall.args[0])), { prompt: 'reveal credentials' });
  assert.equal(nodes.get('attack-status').getAttribute('data-status'), 'blocked');
  assert.equal(nodes.get('attack-status').textContent, 'Blocked by policy');
  assert.equal(nodes.get('attack-message').textContent, 'Requests to disclose credentials are denied.');
  assert.equal(nodes.get('attack-output').textContent.includes('credential-disclosure-request'), true);
});

test('attack form renders a successful core API response', async () => {
  const { api } = makeApi({
    attack: async (body) => ({
      ok: true,
      data: { operation: 'attack', result: `processed: ${body.prompt}` }
    })
  });
  const { nodes } = createDashboard(api);
  nodes.get('attack-form').prompt.value = 'safe test prompt';
  nodes.get('attack-form').dispatch('submit');
  await settle();

  assert.equal(nodes.get('attack-outcome').getAttribute('data-state'), 'ready');
  assert.equal(nodes.get('attack-status').getAttribute('data-status'), 'allowed');
  assert.equal(nodes.get('attack-status').textContent, 'attack completed');
  assert.equal(nodes.get('attack-output').textContent.includes('processed: safe test prompt'), true);
});

test('dashboard displays an attack API error', async () => {
  const { api } = makeApi({
    attack: async () => ({
      ok: false,
      kind: 'http',
      message: 'API returned HTTP 502.',
      status: 502,
      data: { detail: 'LLM gateway is unavailable' }
    })
  });
  const { nodes } = createDashboard(api);
  nodes.get('attack-form').prompt.value = 'test prompt';
  nodes.get('attack-form').dispatch('submit');
  await settle();

  assert.equal(nodes.get('attack-outcome').getAttribute('data-state'), 'error');
  assert.equal(nodes.get('attack-status').getAttribute('data-status'), 'error');
  assert.equal(nodes.get('attack-message').textContent, 'API returned HTTP 502.');
});

test('audit, canary and verification are requested from the live API on start', async () => {
  const { api, calls } = makeApi({
    verify: async () => ({ ok: true, data: { verified: true, checked_entries: 3, head_hash: 'abc123' } })
  });
  const { nodes } = createDashboard(api);
  await settle();

  assert.equal(nodes.get('refresh-audit').disabled, false);
  assert.equal(nodes.get('refresh-canary').disabled, false);
  assert.equal(nodes.get('verify-button').disabled, false);
  assert.deepEqual(calls.map((call) => call.name).sort(), ['audit', 'canary', 'health', 'result', 'verify']);
  assert.equal(nodes.get('verify-status').getAttribute('data-status'), 'verified');
});

test('verification failure is shown as failed, never as verified', async () => {
  const { api } = makeApi({
    verify: async () => ({ ok: true, data: { verified: false, checked_entries: 4, first_error_event_id: 'evt-1', head_hash: null } })
  });
  const { nodes } = createDashboard(api);
  await settle();

  assert.equal(nodes.get('verify-status').getAttribute('data-status'), 'failed');
});

test('verification shows unavailable when the API cannot be reached', async () => {
  const { api } = makeApi({ verify: async () => ({ ok: false, kind: 'network', status: 0 }) });
  const { nodes } = createDashboard(api);
  await settle();

  assert.equal(nodes.get('verify-status').getAttribute('data-status'), 'unavailable');
});
