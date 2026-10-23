/* ==========================================================================
   CanaryChain dashboard controller (Member C, frontend/js/dashboard.js)

   Rules this file follows:
   - All network access goes through window.CanaryAPI (api.js). No fetch().
   - Nothing is invented: every number, status and row comes from an API
     response or is labelled unavailable. All server text is inserted with
     textContent, never innerHTML.
   - Attack and defense submission are OFF until Member A confirms the
     contract (see CONTRACT below). Nothing is ever submitted automatically.
   - The results panel is intentionally inert: PDF p6 shows one GET /result
     and no list endpoint, so there is nothing safe to render yet.
   ========================================================================== */
(function () {
  'use strict';

  var API = window.CanaryAPI || null;

  /* ======================================================================
     CONTRACT GATES: flip a flag only after Member A publishes
     docs/api-contract.md and confirms the request fields for that route.
     ====================================================================== */
  var CONTRACT = {
    attackConfirmed: false,
    defenseConfirmed: false
  };

  /* ======================================================================
     FIELD MAP: UNCONFIRMED. These names mirror the PDF p6 *proposed* minimum
     payloads. Update them when docs/api-contract.md is final. If a response
     does not match, the panel says so; it never guesses.
     ====================================================================== */
  var FIELDS = {
    listKey: 'items',
    eventId: 'event_id',
    timestamp: 'timestamp',
    tenant: 'tenant',
    eventType: 'event_type',
    canaryType: 'canary_type',
    atlas: 'atlas_technique',
    health: { statusKey: 'status', okValue: 'ok' },
    verify: { verified: 'verified', checked: 'checked_entries', firstError: 'first_error_event_id' },
    action: { statusKey: 'status' }
  };

  var MAX_ROWS = 500;
  var MAX_FIELDS = 60;
  var MOBILE_QUERY = '(max-width: 960px)';
  var NAV_SECTIONS = ['overview', 'audit', 'canary', 'attack', 'results', 'defense', 'verify'];

  var IDS = [
    'app', 'nav-toggle', 'sidebar-collapse', 'global-search',
    'health-indicator', 'health-text', 'last-updated', 'refresh-all',
    'card-health', 'card-audit', 'card-canary', 'card-verify',
    'monitor-panel', 'monitor-body', 'monitor-message',
    'audit-panel', 'audit-body', 'audit-message', 'refresh-audit',
    'canary-panel', 'canary-list', 'canary-message', 'refresh-canary',
    'event-detail', 'event-detail-empty', 'event-detail-body', 'event-detail-meta',
    'event-detail-badges', 'event-detail-fields', 'event-detail-raw',
    'attack-form', 'attack-submit', 'attack-outcome', 'attack-status',
    'attack-output', 'attack-message',
    'defense-form', 'defense-submit', 'defense-outcome', 'defense-status',
    'defense-output', 'defense-message',
    'results-panel', 'results-message', 'refresh-results',
    'verify-button', 'verify-status', 'verify-detail', 'verify-message'
  ];

  var els = {};
  var UI = {};
  var ACTIONS = {};
  var mq = null;

  var state = {
    query: '',
    selected: null,
    healthSeq: 0,
    verifySeq: 0,
    refreshing: false,
    sources: {
      audit:  { key: 'audit',  label: 'Audit event',  seq: 0, items: [], loaded: false, ignored: 0 },
      canary: { key: 'canary', label: 'Canary event', seq: 0, items: [], loaded: false, ignored: 0 }
    }
  };

  /* ---------- small helpers ---------- */
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function isObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
  function clip(s, n) { s = String(s); return s.length > n ? s.slice(0, n) + '\u2026' : s; }
  function nowText() { return new Date().toLocaleTimeString(); }
  function describeFailure(res) { return (res && res.message) || 'Request failed.'; }

  /* Text for any server value, or null when nothing was provided. */
  function textOf(v, max) {
    if (v === undefined || v === null || v === '') return null;
    if (typeof v === 'string') return clip(v, max || 300);
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    try {
      var j = JSON.stringify(v);
      return j === undefined ? null : clip(j, max || 300);
    } catch (e) { return null; }
  }
  function fillValue(node, v, max) {
    var t = textOf(v, max);
    if (t === null) { node.textContent = '\u2014'; node.title = 'Not provided by the API'; }
    else { node.textContent = t; }
  }

  function setState(node, s) {
    node.setAttribute('data-state', s);
    if (s === 'loading') node.setAttribute('aria-busy', 'true');
    else node.removeAttribute('aria-busy');
  }
  function setBadge(node, status, text) {
    node.setAttribute('data-status', status);
    node.textContent = text;
  }
  function setCard(card, s, value, note) {
    setState(card, s);
    card.querySelector('[data-field="value"]').textContent = value;
    card.querySelector('[data-field="note"]').textContent = note;
  }
  function renderKv(dl, obj) {
    clear(dl);
    Object.keys(obj).slice(0, MAX_FIELDS).forEach(function (k) {
      var row = el('div', 'kv-row');
      row.appendChild(el('dt', null, clip(k, 80)));
      var dd = el('dd');
      fillValue(dd, obj[k], 1000);
      row.appendChild(dd);
      dl.appendChild(row);
    });
  }

  /* ======================================================================
     Health
     ====================================================================== */
  function loadHealth() {
    var seq = ++state.healthSeq;
    setState(els.healthIndicator, 'loading');
    els.healthText.textContent = 'API health: checking\u2026';
    setCard(els.cardHealth, 'loading', '\u2026', 'Checking\u2026');

    return Promise.resolve().then(function () { return API.health(); }).then(function (res) {
      if (seq !== state.healthSeq) return null;
      if (!res.ok) {
        if (res.kind === 'not_configured') {
          setState(els.healthIndicator, 'unavailable');
          els.healthText.textContent = 'API health: not configured';
          setCard(els.cardHealth, 'unavailable', '\u2014', 'Unavailable: ' + describeFailure(res));
        } else {
          setState(els.healthIndicator, 'error');
          els.healthText.textContent = 'API health: unreachable';
          setCard(els.cardHealth, 'error', 'Unreachable', describeFailure(res));
        }
        return false;
      }
      var status = isObject(res.data) ? res.data[FIELDS.health.statusKey] : undefined;
      if (status === FIELDS.health.okValue) {
        setState(els.healthIndicator, 'ready');
        els.healthText.textContent = 'API health: ok';
        setCard(els.cardHealth, 'ready', 'OK', 'Checked ' + nowText());
      } else {
        var shown = typeof status === 'string' ? clip(status, 40) : null;
        setState(els.healthIndicator, 'unavailable');
        els.healthText.textContent = shown ? 'API health: ' + shown : 'API health: unrecognised response';
        setCard(els.cardHealth, 'unavailable', shown || '\u2014',
          'The server responded, but not with the expected "' + FIELDS.health.statusKey + '" value.');
      }
      return true;
    }).catch(function () {
      if (seq !== state.healthSeq) return null;
      setState(els.healthIndicator, 'error');
      els.healthText.textContent = 'API health: unreachable';
      setCard(els.cardHealth, 'error', 'Unreachable', 'Unexpected error while reading the response.');
      return false;
    });
  }

  /* ======================================================================
     Audit and canary lists
     ====================================================================== */
  function extractItems(data) {
    if (!isObject(data) || !Array.isArray(data[FIELDS.listKey])) return { ok: false };
    var raw = data[FIELDS.listKey];
    var items = raw.filter(isObject);
    return { ok: true, items: items, ignored: raw.length - items.length };
  }

  function searchText(src, item) {
    var keys = src.key === 'audit'
      ? [FIELDS.timestamp, FIELDS.tenant, FIELDS.eventType, FIELDS.atlas]
      : [FIELDS.timestamp, FIELDS.tenant, FIELDS.canaryType, FIELDS.atlas];
    return keys.map(function (k) { return textOf(item[k], 300) || ''; }).join(' ').toLowerCase();
  }

  function visibleEntries(src) {
    var out = [];
    src.items.forEach(function (item, index) {
      if (!state.query || searchText(src, item).indexOf(state.query) !== -1) {
        out.push({ item: item, index: index });
      }
    });
    return out;
  }

  function tableMessage(tbody, text) {
    clear(tbody);
    var tr = el('tr', 'empty-row');
    var td = el('td', null, text);
    td.colSpan = 4;
    tr.appendChild(td);
    tbody.appendChild(tr);
  }

  function renderAuditRows(visible) {
    clear(els.auditBody);
    visible.slice(0, MAX_ROWS).forEach(function (entry) {
      var item = entry.item;
      var tr = el('tr');
      var id = textOf(item[FIELDS.eventId], 80);
      tr.setAttribute('data-event-id', id !== null ? id : 'row-' + entry.index);
      tr.setAttribute('data-index', String(entry.index));
      tr.tabIndex = 0;
      tr.setAttribute('aria-selected', 'false');
      [FIELDS.timestamp, FIELDS.tenant, FIELDS.eventType, FIELDS.atlas].forEach(function (key) {
        var td = el('td');
        fillValue(td, item[key]);
        tr.appendChild(td);
      });
      els.auditBody.appendChild(tr);
    });
  }

  function renderCanaryItems(visible) {
    clear(els.canaryList);
    visible.slice(0, MAX_ROWS).forEach(function (entry) {
      var item = entry.item;
      var li = el('li');
      var btn = el('button', 'event-item');
      btn.type = 'button';
      btn.setAttribute('data-index', String(entry.index));
      btn.setAttribute('aria-current', 'false');

      var type = textOf(item[FIELDS.canaryType], 120);
      btn.appendChild(el('span', 'event-title', type || 'Canary event (type not provided)'));

      var parts = [];
      var tenant = textOf(item[FIELDS.tenant], 80);
      var ts = textOf(item[FIELDS.timestamp], 80);
      var atlas = textOf(item[FIELDS.atlas], 80);
      if (tenant) parts.push(tenant);
      if (ts) parts.push(ts);
      if (atlas) parts.push('ATLAS ' + atlas);
      btn.appendChild(el('span', 'event-meta', parts.length ? parts.join(' \u00b7 ') : 'No details provided'));

      li.appendChild(btn);
      els.canaryList.appendChild(li);
    });
  }

  function markSelection() {
    var sel = state.selected;
    Array.prototype.forEach.call(els.auditBody.querySelectorAll('tr[data-index]'), function (tr) {
      var on = !!sel && sel.source === 'audit' && tr.getAttribute('data-index') === String(sel.index);
      tr.setAttribute('aria-selected', String(on));
    });
    Array.prototype.forEach.call(els.canaryList.querySelectorAll('.event-item'), function (b) {
      var on = !!sel && sel.source === 'canary' && b.getAttribute('data-index') === String(sel.index);
      b.setAttribute('aria-current', String(on));
    });
  }

  function renderList(src) {
    var ui = UI[src.key];
    var total = src.items.length;
    var visible = visibleEntries(src);
    var notes = [];

    if (src.ignored > 0) notes.push(src.ignored + ' entr' + (src.ignored === 1 ? 'y was' : 'ies were') + ' ignored because not an object.');
    if (state.query && visible.length < total) notes.push('Showing ' + visible.length + ' of ' + total + ' loaded (search filter active).');
    if (visible.length > MAX_ROWS) notes.push('Showing the first ' + MAX_ROWS + ' of ' + visible.length + '.');

    setState(ui.panel, total === 0 ? 'empty' : 'ready');

    if (src.key === 'audit') {
      if (total === 0) tableMessage(els.auditBody, 'No audit events returned by the server.');
      else if (visible.length === 0) tableMessage(els.auditBody, 'No loaded audit events match the search.');
      else renderAuditRows(visible);
      els.auditMessage.textContent = notes.join(' ');
    } else {
      clear(els.canaryList);
      if (visible.length) renderCanaryItems(visible);
      if (total === 0) els.canaryMessage.textContent = 'No canary events returned by the server.';
      else if (visible.length === 0) els.canaryMessage.textContent = 'No loaded canary events match the search.';
      else els.canaryMessage.textContent = notes.join(' ');
    }
    markSelection();
  }

  function listFailed(src, st, msg) {
    var ui = UI[src.key];
    src.items = [];
    src.loaded = false;
    src.ignored = 0;
    setState(ui.panel, st);
    if (src.key === 'audit') {
      tableMessage(els.auditBody, 'Unavailable: ' + msg);
      els.auditMessage.textContent = '';
    } else {
      clear(els.canaryList);
      els.canaryMessage.textContent = 'Unavailable: ' + msg;
    }
    setCard(ui.card, st, '\u2014', 'Unavailable: ' + msg);
    afterSourceChange(src);
    renderMonitor();
  }

  function afterSourceChange(src) {
    if (state.selected && state.selected.source === src.key) clearDetail();
  }

  function loadList(src) {
    var ui = UI[src.key];
    var seq = ++src.seq;
    ui.refresh.disabled = true;
    setState(ui.panel, 'loading');
    setCard(ui.card, 'loading', '\u2026', 'Loading\u2026');
    if (src.key === 'audit') {
      tableMessage(els.auditBody, 'Loading\u2026');
      els.auditMessage.textContent = '';
    } else {
      clear(els.canaryList);
      els.canaryMessage.textContent = 'Loading\u2026';
    }

    return Promise.resolve().then(function () { return API[src.key](); }).then(function (res) {
      if (seq !== src.seq) return null;
      ui.refresh.disabled = false;
      if (!res.ok) {
        listFailed(src, res.kind === 'not_configured' ? 'unavailable' : 'error', describeFailure(res));
        return false;
      }
      var parsed = extractItems(res.data);
      if (!parsed.ok) {
        listFailed(src, 'error', 'Unexpected response: expected a list under "' + FIELDS.listKey + '".');
        return false;
      }
      src.items = parsed.items;
      src.ignored = parsed.ignored;
      src.loaded = true;
      afterSourceChange(src);
      renderList(src);
      setCard(ui.card, 'ready', String(src.items.length),
        src.items.length === 0 ? 'The server returned no events.' : 'Loaded ' + nowText());
      renderMonitor();
      return true;
    }).catch(function () {
      if (seq !== src.seq) return null;
      ui.refresh.disabled = false;
      listFailed(src, 'error', 'Unexpected error while reading the response.');
      return false;
    });
  }

  /* ======================================================================
     Monitoring panel: counts only over events that were actually loaded
     ====================================================================== */
  function renderMonitor() {
    clear(els.monitorBody);
    var a = state.sources.audit;
    var c = state.sources.canary;

    if (!a.loaded && !c.loaded) {
      setState(els.monitorPanel, 'unavailable');
      els.monitorMessage.textContent = 'Unavailable: nothing to chart until events are loaded.';
      return;
    }

    var counts = Object.create(null);
    var order = [];
    function add(items, key) {
      items.forEach(function (item) {
        var t = textOf(item[FIELDS.tenant], 60) || '(no tenant field)';
        if (!counts[t]) { counts[t] = { audit: 0, canary: 0 }; order.push(t); }
        counts[t][key] += 1;
      });
    }
    if (a.loaded) add(a.items, 'audit');
    if (c.loaded) add(c.items, 'canary');

    if (order.length === 0) {
      setState(els.monitorPanel, 'empty');
      els.monitorMessage.textContent = 'No events were returned, so there is nothing to summarise.';
      return;
    }

    var dl = el('dl', 'kv');
    order.forEach(function (t) {
      var row = el('div', 'kv-row');
      row.appendChild(el('dt', null, t));
      row.appendChild(el('dd', null, counts[t].audit + ' audit, ' + counts[t].canary + ' canary'));
      dl.appendChild(row);
    });
    els.monitorBody.appendChild(dl);

    var missing = [];
    if (!a.loaded) missing.push('audit');
    if (!c.loaded) missing.push('canary');
    setState(els.monitorPanel, 'ready');
    els.monitorMessage.textContent = 'Counts cover only the events currently loaded in this view' +
      (missing.length ? ' (' + missing.join(' and ') + ' not loaded).' : '.');
  }

  /* ======================================================================
     Selected-event detail
     ====================================================================== */
  function clearDetail() {
    state.selected = null;
    setState(els.eventDetail, 'idle');
    els.eventDetailEmpty.hidden = false;
    els.eventDetailBody.hidden = true;
    clear(els.eventDetailBadges);
    clear(els.eventDetailFields);
    els.eventDetailRaw.textContent = '';
    els.eventDetailMeta.textContent = '';
    markSelection();
  }

  function addBadge(text) {
    var li = el('li');
    var b = el('span', 'badge', text);
    b.setAttribute('data-status', 'none');
    li.appendChild(b);
    els.eventDetailBadges.appendChild(li);
  }

  function selectEvent(sourceKey, index) {
    var src = state.sources[sourceKey];
    var item = src && src.items[index];
    if (!item) return;
    state.selected = { source: sourceKey, index: index };

    var ts = textOf(item[FIELDS.timestamp], 80);
    els.eventDetailMeta.textContent = src.label + (ts ? ' \u00b7 ' + ts : '');

    clear(els.eventDetailBadges);
    addBadge(src.label);
    var atlas = textOf(item[FIELDS.atlas], 80);
    if (atlas) addBadge('ATLAS: ' + atlas);

    renderKv(els.eventDetailFields, item);
    var raw;
    try { raw = JSON.stringify(item, null, 2); } catch (e) { raw = ''; }
    els.eventDetailRaw.textContent = clip(raw || '', 20000);

    setState(els.eventDetail, 'ready');
    els.eventDetailEmpty.hidden = true;
    els.eventDetailBody.hidden = false;
    markSelection();
    els.eventDetail.scrollIntoView({ block: 'nearest' });
  }

  /* ======================================================================
     Verification: "verified", "failed" and "unavailable" stay distinct
     ====================================================================== */
  function setVerify(kind, badgeText, message, details) {
    setBadge(els.verifyStatus, kind, badgeText);
    els.verifyMessage.textContent = message;
    clear(els.verifyDetail);
    (details || []).forEach(function (d) {
      var row = el('div', 'kv-row');
      row.appendChild(el('dt', null, d[0]));
      var dd = el('dd');
      fillValue(dd, d[1], 300);
      row.appendChild(dd);
      els.verifyDetail.appendChild(row);
    });
    var cardState = { verified: 'ready', failed: 'error', checking: 'loading' }[kind] || 'unavailable';
    var cardValue = { verified: 'Verified', failed: 'Failed', checking: 'Checking\u2026',
                      unavailable: 'Unavailable', 'not-checked': 'Not checked' }[kind] || 'Not checked';
    setCard(els.cardVerify, cardState, cardValue, message || 'Unavailable: not requested yet.');
  }

  function verifyDetails(body) {
    var v = FIELDS.verify;
    var rows = [];
    if (!body) return rows;
    if (body[v.checked] !== undefined) rows.push(['Entries checked', body[v.checked]]);
    if (body[v.firstError] !== undefined && body[v.firstError] !== null) rows.push(['First failing entry', body[v.firstError]]);
    return rows;
  }

  function runVerify() {
    var seq = ++state.verifySeq;
    els.verifyButton.disabled = true;
    setVerify('checking', 'Checking\u2026', '', []);

    Promise.resolve().then(function () { return API.verify(); }).then(function (res) {
      if (seq !== state.verifySeq) return;
      els.verifyButton.disabled = false;
      var flagKey = FIELDS.verify.verified;
      var body = isObject(res.data) ? res.data : null;
      var flag = body ? body[flagKey] : undefined;
      var when = nowText();

      if (res.ok) {
        if (flag === true) {
          setVerify('verified', 'Verified', 'Server response received at ' + when + '.', verifyDetails(body));
        } else if (flag === false) {
          setVerify('failed', 'Verification failed', 'The server reported that verification failed (' + when + ').', verifyDetails(body));
        } else {
          setVerify('unavailable', 'Unavailable',
            'Unexpected response: no boolean "' + flagKey + '" field. Nothing is shown as verified.', []);
        }
      } else if (body && flag === false) {
        // The server explicitly reported verified:false, even if via an error status.
        setVerify('failed', 'Verification failed',
          'The server reported that verification failed (HTTP ' + res.status + ', ' + when + ').', verifyDetails(body));
      } else {
        setVerify('unavailable', 'Unavailable', describeFailure(res), []);
      }
    }).catch(function () {
      if (seq !== state.verifySeq) return;
      els.verifyButton.disabled = false;
      setVerify('unavailable', 'Unavailable', 'Unexpected error while reading the response.', []);
    });
  }

  /* ======================================================================
     Attack and defense forms (gated by CONTRACT; never automatic)
     ====================================================================== */
  function formBody(form) {
    var body = {};
    Array.prototype.forEach.call(form.elements, function (c) {
      if (!c.name) return;
      body[c.name] = c.type === 'checkbox' ? c.checked : String(c.value).trim();
    });
    return body;
  }

  function renderAction(a, res) {
    var ui = a.ui;
    clear(ui.output);
    ui.message.textContent = '';

    if (!res.ok) {
      setState(ui.outcome, 'error');
      setBadge(ui.status, 'error', 'Request failed');
      ui.message.textContent = describeFailure(res);
      if (isObject(res.data)) renderKv(ui.output, res.data);
      return;
    }
    if (!isObject(res.data)) {
      setState(ui.outcome, 'error');
      setBadge(ui.status, 'none', 'Response received');
      ui.message.textContent = 'The server response was not an object, so no fields can be shown.';
      return;
    }
    var st = res.data[FIELDS.action.statusKey];
    var known = typeof st === 'string' && a.known.indexOf(st) !== -1;
    setState(ui.outcome, 'ready');
    setBadge(ui.status, known ? st : 'none', typeof st === 'string' ? clip(st, 60) : 'Response received');
    renderKv(ui.output, res.data);
  }

  function submitAction(name) {
    var a = ACTIONS[name];
    var ui = a.ui;

    if (!CONTRACT[a.confirmedKey]) {
      ui.message.textContent = a.label + ' is disabled until Member A confirms the API contract (docs/api-contract.md).';
      return;
    }
    if (!API || !API.isConfigured()) {
      ui.message.textContent = 'Unavailable: API base URL is not configured for this page.';
      return;
    }
    var body = formBody(ui.form);
    var empty = Object.keys(body).some(function (k) { return typeof body[k] === 'string' && body[k] === ''; });
    if (empty) {
      ui.message.textContent = 'Fill in every field before submitting.';
      return;
    }

    ui.submit.disabled = true;
    setState(ui.outcome, 'loading');
    setBadge(ui.status, 'none', 'Sending\u2026');
    clear(ui.output);
    ui.message.textContent = '';

    Promise.resolve().then(function () { return a.call(body); }).then(function (res) {
      ui.submit.disabled = false;
      renderAction(a, res);
    }).catch(function () {
      ui.submit.disabled = false;
      setState(ui.outcome, 'error');
      setBadge(ui.status, 'error', 'Request failed');
      ui.message.textContent = 'Unexpected error while reading the response.';
    });
  }

  /* ======================================================================
     Refresh
     ====================================================================== */
  function refreshAll() {
    if (state.refreshing) return;
    state.refreshing = true;
    els.refreshAll.disabled = true;
    Promise.all([loadHealth(), loadList(state.sources.audit), loadList(state.sources.canary)]).then(function (r) {
      state.refreshing = false;
      els.refreshAll.disabled = false;
      if (r.some(function (x) { return x === true; })) {
        els.lastUpdated.textContent = 'Last updated: ' + nowText();
      }
    });
  }

  function refreshOne(src) {
    loadList(src).then(function (ok) {
      if (ok === true) els.lastUpdated.textContent = 'Last updated: ' + nowText();
    });
  }

  function setAllUnavailable(reason) {
    var msg = 'Unavailable: ' + reason;
    setState(els.healthIndicator, 'unavailable');
    els.healthText.textContent = 'API health: not configured';
    setCard(els.cardHealth, 'unavailable', '\u2014', msg);
    Object.keys(state.sources).forEach(function (k) {
      var src = state.sources[k];
      var ui = UI[k];
      setState(ui.panel, 'unavailable');
      setCard(ui.card, 'unavailable', '\u2014', msg);
      if (k === 'audit') tableMessage(els.auditBody, msg);
      else els.canaryMessage.textContent = msg;
    });
    els.verifyMessage.textContent = msg;
    renderMonitor();
  }

  /* ======================================================================
     Sidebar and navigation
     ====================================================================== */
  function isMobile() { return !!(mq && mq.matches); }

  function sidebarExpanded() {
    var mode = els.app.getAttribute('data-sidebar');
    return isMobile() ? mode === 'open' : mode !== 'collapsed';
  }

  function setInert(node, on) {
    if (!node) return;
    if ('inert' in node) node.inert = on;
    else if (on) node.setAttribute('aria-hidden', 'true');
    else node.removeAttribute('aria-hidden');
  }

  function applySidebar(mode) {
    if (mode) els.app.setAttribute('data-sidebar', mode);
    else els.app.removeAttribute('data-sidebar');
    var expanded = sidebarExpanded();
    els.navToggle.setAttribute('aria-expanded', String(expanded));
    els.sidebarCollapse.setAttribute('aria-expanded', String(expanded));
    var modal = isMobile() && mode === 'open';
    setInert(els.mainColumn, modal);
    if (modal) {
      var target = document.querySelector('.nav-link[aria-current="page"]') || document.querySelector('.nav-link');
      if (target) target.focus();
    }
  }

  function setActiveNav(name) {
    Array.prototype.forEach.call(document.querySelectorAll('.nav-link'), function (a) {
      if (a.getAttribute('data-nav') === name) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
  }

  function wireSidebar() {
    mq = window.matchMedia ? window.matchMedia(MOBILE_QUERY) : null;
    applySidebar('');

    els.navToggle.addEventListener('click', function () {
      if (isMobile()) applySidebar(sidebarExpanded() ? '' : 'open');
      else applySidebar('');
    });

    els.sidebarCollapse.addEventListener('click', function () {
      applySidebar(isMobile() ? '' : 'collapsed');
      els.navToggle.focus();
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && isMobile() && els.app.getAttribute('data-sidebar') === 'open') {
        applySidebar('');
        els.navToggle.focus();
      }
    });

    els.app.addEventListener('click', function (e) {
      // The dim backdrop is a pseudo-element of .app, so its clicks target .app itself.
      if (e.target === els.app && isMobile() && els.app.getAttribute('data-sidebar') === 'open') applySidebar('');
    });

    Array.prototype.forEach.call(document.querySelectorAll('.nav-link'), function (a) {
      a.addEventListener('click', function () {
        setActiveNav(a.getAttribute('data-nav'));
        if (isMobile() && els.app.getAttribute('data-sidebar') === 'open') applySidebar('');
      });
    });

    if (mq) {
      var onChange = function () { applySidebar(''); };
      if (mq.addEventListener) mq.addEventListener('change', onChange);
      else if (mq.addListener) mq.addListener(onChange);
    }

    var hash = (window.location.hash || '').replace('#section-', '');
    if (NAV_SECTIONS.indexOf(hash) !== -1) setActiveNav(hash);

    if ('IntersectionObserver' in window) {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
          if (en.isIntersecting) setActiveNav(en.target.id.replace('section-', ''));
        });
      }, { rootMargin: '-20% 0px -70% 0px', threshold: 0 });
      NAV_SECTIONS.forEach(function (name) {
        var section = document.getElementById('section-' + name);
        if (section) io.observe(section);
      });
    }
  }

  /* ======================================================================
     Init
     ====================================================================== */
  function init() {
    var missing = [];
    IDS.forEach(function (id) {
      var node = document.getElementById(id);
      var key = id.replace(/-([a-z])/g, function (m, c) { return c.toUpperCase(); });
      if (node) els[key] = node; else missing.push(id);
    });
    els.mainColumn = document.querySelector('.main-column');
    if (missing.length || !els.mainColumn) {
      if (window.console && console.error) {
        console.error('[dashboard] index.html is missing expected elements:', missing.join(', '));
      }
      return;
    }

    UI.audit = { panel: els.auditPanel, refresh: els.refreshAudit, card: els.cardAudit };
    UI.canary = { panel: els.canaryPanel, refresh: els.refreshCanary, card: els.cardCanary };

    ACTIONS.attack = {
      label: 'Attack submission', confirmedKey: 'attackConfirmed', known: ['allowed', 'blocked', 'error'],
      call: function (b) { return API.attack(b); },
      ui: { form: els.attackForm, submit: els.attackSubmit, outcome: els.attackOutcome,
            status: els.attackStatus, output: els.attackOutput, message: els.attackMessage }
    };
    ACTIONS.defense = {
      label: 'Defense rule submission', confirmedKey: 'defenseConfirmed', known: ['saved', 'error'],
      call: function (b) { return API.defense(b); },
      ui: { form: els.defenseForm, submit: els.defenseSubmit, outcome: els.defenseOutcome,
            status: els.defenseStatus, output: els.defenseOutput, message: els.defenseMessage }
    };

    wireSidebar();

    /* Search: filters only events that are already loaded. */
    els.globalSearch.addEventListener('input', function () {
      state.query = els.globalSearch.value.trim().toLowerCase();
      Object.keys(state.sources).forEach(function (k) {
        if (state.sources[k].loaded) renderList(state.sources[k]);
      });
    });

    /* Event selection (delegated). */
    els.auditBody.addEventListener('click', function (e) {
      var tr = e.target.closest('tr[data-index]');
      if (tr) selectEvent('audit', Number(tr.getAttribute('data-index')));
    });
    els.auditBody.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      var tr = e.target.closest('tr[data-index]');
      if (!tr) return;
      e.preventDefault();
      selectEvent('audit', Number(tr.getAttribute('data-index')));
    });
    els.canaryList.addEventListener('click', function (e) {
      var btn = e.target.closest('.event-item');
      if (btn) selectEvent('canary', Number(btn.getAttribute('data-index')));
    });

    /* Forms: always intercepted; submission only when the contract is confirmed. */
    var configured = !!(API && API.isConfigured());
    Object.keys(ACTIONS).forEach(function (name) {
      var a = ACTIONS[name];
      a.ui.form.addEventListener('submit', function (e) { e.preventDefault(); submitAction(name); });
      if (CONTRACT[a.confirmedKey] && configured) {
        a.ui.submit.disabled = false;
      } else {
        a.ui.submit.disabled = true;
        a.ui.message.textContent = a.label + ' is disabled until Member A confirms the API contract (docs/api-contract.md).';
      }
    });

    /* Results stay inert: no list endpoint is defined in the PDF (p6). */
    els.refreshResults.disabled = true;
    els.resultsMessage.textContent =
      'Unavailable: the contract does not yet define how to list results (open question for Member A).';

    if (!API) {
      if (window.console && console.error) console.error('[dashboard] window.CanaryAPI is missing; api.js did not load.');
      setAllUnavailable('the API client (api.js) did not load.');
      return;
    }
    if (!configured) {
      setAllUnavailable('API base URL is not configured for this page.');
      return;
    }

    /* Read-only controls. Reading data never submits anything. */
    els.refreshAll.disabled = false;
    els.refreshAudit.disabled = false;
    els.refreshCanary.disabled = false;
    els.verifyButton.disabled = false;

    els.refreshAll.addEventListener('click', refreshAll);
    els.refreshAudit.addEventListener('click', function () { refreshOne(state.sources.audit); });
    els.refreshCanary.addEventListener('click', function () { refreshOne(state.sources.canary); });
    els.verifyButton.addEventListener('click', runVerify);

    refreshAll();   // read-only GETs: health, audit, canary. Never attack or defense.
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();