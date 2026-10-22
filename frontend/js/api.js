/* ==========================================================================
   CanaryChain dashboard: API client (Member C, frontend/js/api.js)

   This is the ONLY file that makes network requests. dashboard.js must call
   window.CanaryAPI and never use fetch() directly.

   What this file does NOT do:
   - It does not decide allowed/blocked, verified/failed, or healthy/unhealthy.
     It returns what the server said; dashboard.js shows it.
   - It does not define request or response fields. Bodies and query
     parameters are passed through exactly as the caller supplies them.
   - It never returns ok:true unless the server answered with an HTTP 2xx
     status AND a body that is empty or valid JSON.

   Result shape (every call returns a Promise that RESOLVES; it never rejects):
     success: { ok: true,  status: <number>, data: <parsed JSON or null> }
     failure: { ok: false, kind: <string>, message: <string>,
                status: <number|null>, data: <parsed JSON error body|null>,
                cause?: <string> }
   Failure kinds:
     not_configured  base URL / endpoint not usable (e.g. page opened from file://)
     invalid_request caller input could not be turned into a safe request
     network         the API could not be reached (offline, refused, CORS block)
     timeout         no complete response within timeoutMs
     aborted         cancelled by the caller
     http            the server answered with a non-2xx status
     invalid_json    a 2xx response whose body was not valid JSON
     unsupported     the browser lacks fetch / AbortController

   NOTE: ok:true means "the server answered successfully". It does not mean
   "the service is healthy" or "the chain is verified". Inspect `data`
   according to the final contract (docs/api-contract.md, owned by Member A).
   ========================================================================== */
(function (global) {
  'use strict';

  /* ======================================================================
     The dashboard and API share an origin. Nginx serves the page and proxies
     /api/* to the core API, stripping the /api prefix.
     ====================================================================== */
  var DEFAULTS = {
    apiBaseUrl: '',
    timeoutMs: 8000,
    credentials: 'same-origin', // 'omit' | 'same-origin' | 'include'
    endpoints: {
      health:  { method: 'GET',  path: '/api/health' },
      attack:  { method: 'POST', path: '/api/attack' },
      defense: { method: 'POST', path: '/api/defense' },
      result:  { method: 'GET',  path: '/api/result' },
      audit:   null,
      canary:  null,
      verify:  null
    }
  };

  var ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
  var ALLOWED_CREDENTIALS = ['omit', 'same-origin', 'include'];
  var PATH_PATTERN = /^\/(?!\/)[^\s\\?#]*$/;   // one leading "/", no host tricks
  var MAX_TIMEOUT_MS = 120000;

  /* ---------- internal state ---------- */
  var config = cloneDefaults();

  function cloneDefaults() {
    var eps = {};
    Object.keys(DEFAULTS.endpoints).forEach(function (k) {
      var endpoint = DEFAULTS.endpoints[k];
      eps[k] = endpoint ? { method: endpoint.method, path: endpoint.path } : null;
    });
    return {
      apiBaseUrl: DEFAULTS.apiBaseUrl,
      timeoutMs: DEFAULTS.timeoutMs,
      credentials: DEFAULTS.credentials,
      endpoints: eps
    };
  }

  function validBase(base) {
    var u;
    try { u = new URL(base); } catch (e) { return false; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    if (u.username || u.password || u.search || u.hash) return false;
    return true;
  }

  /* Applies valid settings, skips invalid ones, returns a list of problems. */
  function applyConfig(partial) {
    var problems = [];
    if (!partial || typeof partial !== 'object') {
      return ['configuration must be an object'];
    }

    if ('apiBaseUrl' in partial) {
      if (typeof partial.apiBaseUrl !== 'string') {
        problems.push('apiBaseUrl must be a string');
      } else {
        var base = partial.apiBaseUrl.trim().replace(/\/+$/, '');
        if (base !== '' && !validBase(base)) {
          problems.push('apiBaseUrl must be an http(s) URL without credentials, query or hash, or empty for same-origin');
        } else {
          config.apiBaseUrl = base;
        }
      }
    }

    if ('timeoutMs' in partial) {
      var t = partial.timeoutMs;
      if (typeof t !== 'number' || !isFinite(t) || t <= 0 || t > MAX_TIMEOUT_MS) {
        problems.push('timeoutMs must be a number between 1 and ' + MAX_TIMEOUT_MS);
      } else {
        config.timeoutMs = t;
      }
    }

    if ('credentials' in partial) {
      if (ALLOWED_CREDENTIALS.indexOf(partial.credentials) === -1) {
        problems.push('credentials must be one of: ' + ALLOWED_CREDENTIALS.join(', '));
      } else {
        config.credentials = partial.credentials;
      }
    }

    if ('endpoints' in partial) {
      var eps = partial.endpoints;
      if (!eps || typeof eps !== 'object') {
        problems.push('endpoints must be an object');
      } else {
        Object.keys(eps).forEach(function (key) {
          if (!Object.prototype.hasOwnProperty.call(DEFAULTS.endpoints, key)) {
            problems.push("unknown endpoint '" + key + "' (this client only supports: " +
                          Object.keys(DEFAULTS.endpoints).join(', ') + ')');
            return;
          }
          var value = eps[key];
          if (value === null) { config.endpoints[key] = null; return; }   // disable
          if (typeof value !== 'object') {
            problems.push("endpoint '" + key + "' must be an object or null");
            return;
          }
          var fallback = DEFAULTS.endpoints[key] || { method: 'GET', path: '/api/' + key };
          var current = config.endpoints[key] ||
                        { method: fallback.method, path: fallback.path };
          var next = { method: current.method, path: current.path };
          var ok = true;
          if ('method' in value) {
            var m = String(value.method).toUpperCase();
            if (ALLOWED_METHODS.indexOf(m) === -1) {
              problems.push("endpoint '" + key + "': method must be one of " + ALLOWED_METHODS.join(', '));
              ok = false;
            } else { next.method = m; }
          }
          if ('path' in value) {
            if (typeof value.path !== 'string' || !PATH_PATTERN.test(value.path)) {
              problems.push("endpoint '" + key + "': path must start with a single '/' and contain no spaces, '\\', '?' or '#'");
              ok = false;
            } else { next.path = value.path; }
          }
          if (ok) config.endpoints[key] = next;
        });
      }
    }

    return problems;
  }

  /* Optional pre-load override: define window.CANARY_CONFIG before this script. */
  if (global.CANARY_CONFIG !== undefined) {
    var initialProblems = applyConfig(global.CANARY_CONFIG);
    if (initialProblems.length && global.console && global.console.warn) {
      global.console.warn('[CanaryAPI] ignored invalid CANARY_CONFIG settings:', initialProblems);
    }
  }

  /* ---------- helpers ---------- */
  function fail(kind, message, extra) {
    var out = { ok: false, kind: kind, message: message, status: null, data: null };
    if (extra) {
      if (extra.status !== undefined) out.status = extra.status;
      if (extra.data !== undefined) out.data = extra.data;
      if (extra.cause) out.cause = extra.cause;
    }
    return out;
  }

  /* Where requests go, or null if the page has no usable API location. */
  function resolveTarget() {
    var base = config.apiBaseUrl;
    if (base === '') {
      var proto = global.location && global.location.protocol;
      if (proto !== 'http:' && proto !== 'https:') return null;   // e.g. file://
      return { prefix: '', origin: global.location.origin };
    }
    if (!validBase(base)) return null;
    return { prefix: base, origin: new URL(base).origin };
  }

  /* Builds the final URL. Never allows a request to leave the target origin. */
  function buildUrl(target, endpoint, params) {
    var url;
    try {
      url = new URL(target.prefix + endpoint.path, target.origin);
    } catch (e) {
      return { error: 'Could not build the request URL.' };
    }
    if (url.origin !== target.origin) {
      return { error: 'Request URL does not match the configured API origin.' };
    }
    if (params !== undefined && params !== null) {
      if (typeof params !== 'object' || Array.isArray(params)) {
        return { error: 'params must be a plain object.' };
      }
      var keys = Object.keys(params);
      for (var i = 0; i < keys.length; i++) {
        var value = params[keys[i]];
        if (value === undefined || value === null) continue;
        var list = Array.isArray(value) ? value : [value];
        for (var j = 0; j < list.length; j++) {
          var item = list[j];
          if (item !== null && typeof item === 'object') {
            return { error: "params['" + keys[i] + "'] must be a string, number or boolean." };
          }
          url.searchParams.append(keys[i], String(item));
        }
      }
    }
    return { url: url.toString() };
  }

  function parseJson(text) {
    if (text.trim() === '') return { valid: true, data: null };
    try { return { valid: true, data: JSON.parse(text) }; }
    catch (e) { return { valid: false, data: null }; }
  }

  function interpret(resp, text) {
    var parsed = parseJson(text);
    if (resp.ok) {
      if (!parsed.valid) {
        return fail('invalid_json', 'API response was not valid JSON.', { status: resp.status });
      }
      return { ok: true, status: resp.status, data: parsed.data };
    }
    return fail('http', 'API returned HTTP ' + resp.status + '.', {
      status: resp.status,
      data: parsed.valid ? parsed.data : null
    });
  }

  /* ---------- the single place that calls fetch() ---------- */
  function call(name, opts) {
    opts = opts || {};

    var endpoint = config.endpoints[name];
    if (!endpoint) {
      return Promise.resolve(fail('not_configured', "Endpoint '" + name + "' is not configured."));
    }
    if (typeof global.fetch !== 'function' || typeof global.AbortController !== 'function') {
      return Promise.resolve(fail('unsupported', 'This browser cannot make API requests.'));
    }

    var target = resolveTarget();
    if (!target) {
      return Promise.resolve(fail('not_configured', 'API base URL is not configured for this page.'));
    }

    var built = buildUrl(target, endpoint, opts.params);
    if (built.error) {
      return Promise.resolve(fail('invalid_request', built.error));
    }

    var init = {
      method: endpoint.method,
      headers: { 'Accept': 'application/json' },
      credentials: config.credentials,
      cache: 'no-store',
      redirect: 'follow'
    };

    if (opts.body !== undefined) {
      if (endpoint.method === 'GET') {
        return Promise.resolve(fail('invalid_request', 'GET requests cannot carry a body.'));
      }
      var serialized;
      try { serialized = JSON.stringify(opts.body); }
      catch (e) { return Promise.resolve(fail('invalid_request', 'Request body could not be converted to JSON.')); }
      if (serialized === undefined) {
        return Promise.resolve(fail('invalid_request', 'Request body could not be converted to JSON.'));
      }
      init.body = serialized;
      init.headers['Content-Type'] = 'application/json';
    }

    var timeoutMs = config.timeoutMs;
    var controller = new AbortController();
    var timedOut = false;
    var timer = setTimeout(function () { timedOut = true; controller.abort(); }, timeoutMs);

    var external = opts.signal || null;
    var onExternalAbort = function () { controller.abort(); };
    if (external) {
      if (external.aborted) {
        clearTimeout(timer);
        return Promise.resolve(fail('aborted', 'Request was cancelled.'));
      }
      external.addEventListener('abort', onExternalAbort);
    }
    init.signal = controller.signal;

    function cleanup() {
      clearTimeout(timer);
      if (external) external.removeEventListener('abort', onExternalAbort);
    }

    return Promise.resolve()
      .then(function () { return global.fetch(built.url, init); })
      .then(function (resp) {
        return resp.text().then(function (text) { return { resp: resp, text: text }; });
      })
      .then(function (r) {
        cleanup();
        return interpret(r.resp, r.text);
      })
      .catch(function (err) {
        cleanup();
        if (timedOut) return fail('timeout', 'Request timed out after ' + timeoutMs + ' ms.');
        if (controller.signal.aborted) return fail('aborted', 'Request was cancelled.');
        return fail('network', 'Could not reach the API.', {
          cause: err && err.message ? String(err.message) : null
        });
      });
  }

  function withOptions(opts, extra) {
    var out = {};
    var source = opts || {};
    Object.keys(source).forEach(function (k) { out[k] = source[k]; });
    Object.keys(extra).forEach(function (k) { out[k] = extra[k]; });
    return out;
  }

  /* ---------- public API ---------- */
  /* opts (all optional): { signal: AbortSignal, params: {...query...} } */
  global.CanaryAPI = Object.freeze({
    /* Configuration */
    configure: function (partial) {
      var problems = applyConfig(partial);
      return { ok: problems.length === 0, problems: problems };
    },
    getConfig: function () {
      return JSON.parse(JSON.stringify(config));
    },
    isConfigured: function () {
      return resolveTarget() !== null;
    },

    /* Calls. Bodies and params are passed through exactly as given. */
    health:  function (opts)         { return call('health', opts); },
    attack:  function (body, opts)   { return call('attack',  withOptions(opts, { body: body })); },
    defense: function (body, opts)   { return call('defense', withOptions(opts, { body: body })); },
    result:  function (params, opts) { return call('result',  withOptions(opts, { params: params })); },
    audit:   function (params, opts) { return call('audit',   withOptions(opts, { params: params })); },
    canary:  function (params, opts) { return call('canary',  withOptions(opts, { params: params })); },
    verify:  function (opts)         { return call('verify', opts); }
  });
})(window);