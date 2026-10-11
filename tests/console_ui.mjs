// Exercise the console's shipped app.js (busy buttons, the double-submit guard, quiet background refreshes, inline errors,
// the live-stream indicator) without a browser: a small DOM fake, manual timers and a manual clock.
// docs/design/console-loading-states.md
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../src/oarbank/console/static/app.js', import.meta.url), 'utf8');

// ---------------------------------------------------------------- a DOM fake: just what app.js touches
class Node {
  constructor() { this.parentNode = null; this.children = []; this.listeners = []; }
  get firstChild() { return this.children[0] || null; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.children.push(c); return c; }
  insertBefore(c, ref) {
    if (!ref) return this.appendChild(c);
    if (c.parentNode) c.parentNode.removeChild(c);
    c.parentNode = this; this.children.splice(this.children.indexOf(ref), 0, c); return c;
  }
  removeChild(c) { this.children = this.children.filter(x => x !== c); c.parentNode = null; return c; }
  contains(n) { for (; n; n = n.parentNode) if (n === this) return true; return false; }
  addEventListener(type, fn, capture) { this.listeners.push({type, fn, capture: capture === true || !!(capture && capture.capture)}); }
  removeEventListener() {}
  *walk() { for (const c of this.children) { yield c; yield* c.walk(); } }
  querySelectorAll(sel) { return [...this.walk()].filter(e => e.matches && e.matches(sel)); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}
function parseCompound(s) {
  const m = {tag: null, id: null, classes: [], attrs: []};
  const re = /^([a-zA-Z]+)|#([\w-]+)|\.([\w-]+)|\[([\w-]+)(?:=["']?([^"'\]]*)["']?)?\]/g;
  let x, at = 0;
  while ((x = re.exec(s.slice(at))) && x[0]) {
    if (x[1]) m.tag = x[1].toUpperCase(); else if (x[2]) m.id = x[2]; else if (x[3]) m.classes.push(x[3]);
    else m.attrs.push([x[4], x[5]]);
    at += x[0].length; re.lastIndex = 0;
  }
  if (at !== s.length) throw new Error('unsupported selector ' + s);
  return m;
}
class Element extends Node {
  constructor(tag) {
    super();
    this.tagName = tag.toUpperCase(); this.attrs = {}; this.style = {}; this.text = ''; this.disabled = false; this.hidden = false;
    const self = this;
    this.dataset = new Proxy({}, {
      get: (_, k) => self.attrs['data-' + k.replace(/[A-Z]/g, c => '-' + c.toLowerCase())],
      set: (_, k, v) => { self.attrs['data-' + k.replace(/[A-Z]/g, c => '-' + c.toLowerCase())] = String(v); return true; },
      deleteProperty: (_, k) => { delete self.attrs['data-' + k.replace(/[A-Z]/g, c => '-' + c.toLowerCase())]; return true; },
    });
    this.classList = {
      add: c => { const s = new Set(self.className.split(' ').filter(Boolean)); s.add(c); self.className = [...s].join(' '); },
      remove: c => { self.className = self.className.split(' ').filter(x => x && x !== c).join(' '); },
      contains: c => self.className.split(' ').includes(c),
      toggle: (c, on) => { (on ? self.classList.add : self.classList.remove)(c); },
    };
  }
  get className() { return this.attrs.class || ''; }
  set className(v) { this.attrs.class = v; }
  get id() { return this.attrs.id || ''; }
  set id(v) { this.attrs.id = v; }
  get type() { return this.attrs.type || (this.tagName === 'BUTTON' ? 'submit' : 'text'); }
  set type(v) { this.attrs.type = v; }
  get name() { return this.attrs.name; }
  set name(v) { this.attrs.name = v; }
  get textContent() { return this.children.length ? this.children.map(c => c.textContent).join('') : this.text; }
  set textContent(v) { for (const c of [...this.children]) this.removeChild(c); this.text = String(v); }
  get innerHTML() { return this.children.length ? this.children.map(c => `<${c.tagName.toLowerCase()} class="${c.className}">${c.textContent}</>`).join('') : this.text; }
  set innerHTML(v) { this.textContent = v; }               // restoring a saved label: plain text in these tests
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  removeAttribute(k) { delete this.attrs[k]; }
  hasAttribute(k) { return k in this.attrs; }
  matches(sel) {
    return sel.split(',').some(part => {
      const m = parseCompound(part.trim());
      if (m.tag && m.tag !== this.tagName) return false;
      if (m.id && m.id !== this.id) return false;
      if (m.classes.some(c => !this.classList.contains(c))) return false;
      return m.attrs.every(([k, v]) => k in this.attrs && (v === undefined || this.attrs[k] === v));
    });
  }
  closest(sel) { for (let n = this; n instanceof Element; n = n.parentNode) if (n.matches(sel)) return n; return null; }
  getBoundingClientRect() { return {width: 96, height: 24}; }
  focus() { doc.activeElement = this; }
}
class HTMLFormElement extends Element {
  get method() { return this.attrs.method || 'get'; }
  requestSubmit(btn) { dispatch(this, new Event('submit', {bubbles: true, submitter: btn})); }
}
class Event {
  constructor(type, init = {}) { Object.assign(this, {type, bubbles: !!init.bubbles, detail: init.detail, submitter: init.submitter, defaultPrevented: false, stopped: false}); }
  preventDefault() { this.defaultPrevented = true; }
  stopImmediatePropagation() { this.stopped = true; }
  stopPropagation() { this.stopped = true; }
}
function dispatch(target, ev) {
  ev.target = target;
  const path = [];
  for (let n = target; n; n = n.parentNode) path.push(n);
  path.push(win);
  const run = (n, capture) => {
    for (const l of n.listeners) {
      if (ev.stopped) return;
      if (l.type === ev.type && l.capture === capture) l.fn.call(n, ev);
    }
  };
  for (const n of [...path].reverse()) { run(n, true); if (ev.stopped) return ev; }
  for (const n of path) { if (n !== target && !ev.bubbles) break; run(n, false); if (ev.stopped) return ev; }
  return ev;
}
const el = (tag, attrs = {}, kids = []) => {
  const e = tag === 'form' ? new HTMLFormElement('form') : new Element(tag);
  for (const [k, v] of Object.entries(attrs)) if (k === 'text') e.text = v; else e.setAttribute(k, v);
  for (const k of kids) e.appendChild(k);
  return e;
};

// ---------------------------------------------------------------- the page
let clock = 1_000_000, nextTimer = 1, doc, win;
const timers = new Map(), intervals = new Map();
function page({live = true} = {}) {
  timers.clear(); intervals.clear();
  doc = new Node();
  doc.activeElement = null;
  doc.readyState = 'complete';
  doc.getElementById = id => [...doc.walk()].find(e => e.id === id) || null;
  doc.createElement = tag => el(tag);
  doc.createRange = () => ({selectNodeContents() {}});
  const html = el('html');
  doc.appendChild(html);
  const head = el('head', {}, [el('meta', {name: 'csrf-token', content: 'tok'})]);
  head.children[0].content = 'tok';
  const body = el('body', live ? {'sse-connect': '/sse', 'data-boot': 'b1'} : {});
  html.appendChild(head); html.appendChild(body);
  body.appendChild(el('div', {id: 'stale-banner'}, [el('span', {id: 'stale-msg'}), el('span', {id: 'stale-age'})]));
  body.appendChild(el('span', {id: 'live', 'data-state': 'connecting'}, [el('span', {class: 'live-text', text: 'Connecting…'})]));
  body.appendChild(el('time', {id: 'as-of'}));
  doc.body = body;
  doc.activeElement = body;
  win = new Node();
  const FakeDate = class extends Date { constructor(...a) { super(...(a.length ? a : [clock])); } static now() { return clock; } };
  const context = vm.createContext({
    document: doc, window: null, navigator: {onLine: true}, HTMLFormElement, Element, Event, URL, Date: FakeDate,
    setTimeout: (fn, ms) => { const id = nextTimer++; timers.set(id, {fn, at: clock + (ms || 0)}); return id; },
    clearTimeout: id => timers.delete(id),
    setInterval: (fn, ms) => { const id = nextTimer++; intervals.set(id, {fn, ms, at: clock + ms}); return id; },
    clearInterval: id => intervals.delete(id),
    console,
  });
  win.location = {href: 'http://127.0.0.1:7400/', origin: 'http://127.0.0.1:7400', pathname: '/', search: '', reload() { win.reloaded = true; }};
  win.confirm = () => win.answer !== false;
  win.prompt = () => 'because';
  win.isSecureContext = false;
  context.window = win;
  Object.assign(context, {location: win.location});
  for (const k of ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval']) win[k] = context[k];
  vm.runInContext(source, context);
  return {doc, body, win, ui: win.OarbankUI, context};
}
// advance the clock, running timers and intervals that fall due
function advance(ms) {
  const end = clock + ms;
  for (;;) {
    const due = [...timers.entries()].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
    const iv = [...intervals.entries()].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
    const next = [due, iv].filter(Boolean).sort((a, b) => a[1].at - b[1].at)[0];
    if (!next) break;
    clock = Math.max(clock, next[1].at);
    if (next === due) { timers.delete(due[0]); due[1].fn(); } else { iv[1].at += iv[1].ms; iv[1].fn(); }
  }
  clock = end;
}
const announced = () => doc.getElementById('announcer').textContent;
function opForm(label, attrs = {}) {
  const btn = el('button', {title: 'x', text: label});
  const f = el('form', {method: 'post', action: '/do/nodes.pause', ...attrs},
               [el('input', {type: 'hidden', name: 'target', value: 'n1'}), el('input', {type: 'hidden', name: 'csrf', value: 'tok'}), btn]);
  return {f, btn};
}
const submit = (f, btn) => dispatch(f, new Event('submit', {bubbles: true, submitter: btn}));

// ---------------------------------------------------------------- busy labels
{
  const {ui} = page();
  const label = (text, busy) => ui.busyLabel(Object.assign(el('button', {text}), busy ? {} : {}));
  assert.equal(label('Revoke'), 'Revoking…');
  assert.equal(label('Approve…'), 'Approving…');
  assert.equal(label('Apply nodes.pause'), 'Applying…');
  assert.equal(label('Sign out'), 'Signing out…');
  assert.equal(label('Turn off owner signing'), 'Turning off…');
  assert.equal(label('Set'), 'Setting…');
  assert.equal(label('Review install…'), 'Preparing review…');
  assert.equal(label('Canary on this node…'), 'Working…');
  assert.equal(ui.busyLabel(el('button', {text: 'Create join code…', 'data-busy-label': 'Preparing review…'})), 'Preparing review…');
  assert.equal(ui.seconds(12000), '12 s');
  assert.equal(ui.seconds(65000), '1 min 5 s');
}

// ---------------------------------------------------------------- a submitted operation: busy, guarded, elapsed time, restored
{
  const {body, win, ui} = page();
  const {f, btn} = opForm('Pause');
  body.appendChild(f);
  const ev = submit(f, btn);
  assert.equal(ev.defaultPrevented, false, 'the submission goes ahead');
  assert.equal(f.dataset.busy, '1', 'marked at once');
  assert.equal(btn.disabled, false, 'the button is disabled only after the form data is built');
  advance(0);
  assert.equal(btn.disabled, true);
  assert.equal(btn.getAttribute('aria-disabled'), 'true');
  assert.equal(f.getAttribute('aria-busy'), 'true');
  assert.equal(btn.style.minWidth, '96px', 'never narrower than it was');
  assert.ok(btn.querySelector('.spin') && btn.querySelector('.busy-label').textContent === 'Pausing…');
  assert.equal(ui.state().navigating, true, 'the top progress bar runs');
  assert.ok(body.querySelector('.topbar').classList.contains('is-active'));
  advance(100);
  assert.equal(announced(), 'Pausing…');
  // a second submit (double click, Enter) is dropped before it can confirm or post
  assert.equal(submit(f, btn).defaultPrevented, true);
  advance(9000);
  assert.equal(btn.querySelector('.busy-elapsed').textContent, '', 'no elapsed time under 10 s');
  advance(1500);
  assert.match(btn.querySelector('.busy-elapsed').textContent, /^1[01] s$/, 'the elapsed time past 10 s');
  advance(100);
  assert.match(announced(), /Pausing: still working, 1[01] s\./);
  const once = announced();
  advance(5000);
  assert.equal(announced(), once, 'announced once, not every second');
  // back to this page from the back/forward cache: the button works again
  dispatch(win, Object.assign(new Event('pageshow'), {persisted: true}));
  assert.equal(btn.disabled, false);
  assert.equal(btn.textContent, 'Pause');
  assert.equal(f.dataset.busy, undefined);
  assert.equal(f.getAttribute('aria-busy'), null);
  assert.equal(ui.state().navigating, false);
}

// ---------------------------------------------------------------- confirmation declined, a new tab, opting out
{
  const {body, win, ui} = page();
  const {f, btn} = opForm('Revoke', {'data-confirm': 'Revoke?'});
  body.appendChild(f);
  win.answer = false;
  assert.equal(submit(f, btn).defaultPrevented, true);
  advance(10);
  assert.equal(btn.disabled, false);
  assert.equal(f.dataset.busy, undefined, 'a declined confirmation leaves the form usable');
  win.answer = true;
  const tab = opForm('Approve…', {target: '_blank'});
  body.appendChild(tab.f);
  submit(tab.f, tab.btn);
  advance(0);
  assert.equal(tab.btn.disabled, true, 'held against a double click');
  assert.equal(tab.btn.textContent, 'Approve…', 'no busy label: this page stays');
  assert.equal(ui.state().navigating, false);
  advance(1600);
  assert.equal(tab.btn.disabled, false);
  assert.equal(tab.f.dataset.busy, undefined);
}

// ---------------------------------------------------------------- htmx: quiet background refreshes, loud user requests
function xhrEvent(type, target, elt, {xhr, trigger, status} = {}) {
  return dispatch(elt, new Event(type, {bubbles: true, detail: {xhr, target, elt, requestConfig: {verb: 'get', path: '/frag/fleet',
    triggeringEvent: trigger ? {type: trigger} : undefined}}}));
}
{
  const {body, ui} = page();
  const tile = el('div', {id: 'fleet', class: 'live-tile', 'hx-get': '/frag/fleet', 'hx-trigger': 'sse:tick, sse:resync'},
                  [el('p', {text: 'old'})]);
  body.appendChild(tile);
  const xhr = {status: 500};
  const before = xhrEvent('htmx:beforeRequest', tile, tile, {xhr, trigger: 'sse:tick'});
  assert.equal(before.defaultPrevented, false);
  assert.equal(tile.getAttribute('aria-busy'), null, 'a background refresh never sets aria-busy');
  assert.equal(ui.state().userRequests, 0, 'nor runs the progress bar');
  xhrEvent('htmx:responseError', tile, tile, {xhr});
  xhrEvent('htmx:afterRequest', tile, tile, {xhr});
  const note = tile.querySelector('.req-error');
  assert.ok(note, 'a failed refresh says so');
  assert.equal(note.getAttribute('role'), 'status', 'quietly');
  assert.match(note.textContent, /Not refreshed at .*HTTP 500.*out of date/);
  assert.ok(note.querySelector('button').textContent === 'Retry');
  assert.equal(tile.children[1].textContent, 'old', 'the old content stays');
  // the next failure updates the same note instead of adding (and announcing) another
  const xhr2 = {status: 0};
  xhrEvent('htmx:beforeRequest', tile, tile, {xhr: xhr2, trigger: 'sse:tick'});
  xhrEvent('htmx:sendError', tile, tile, {xhr: xhr2});
  assert.equal(tile.querySelectorAll('.req-error').length, 1);
  assert.match(tile.querySelector('.req-error').textContent, /could not be reached/);
  // a successful swap clears it
  dispatch(tile, new Event('htmx:beforeSwap', {bubbles: true, detail: {target: tile, shouldSwap: true}}));
  assert.equal(tile.querySelector('.req-error'), null);

  // a user request: aria-busy on the region, the progress bar, and a loud error
  const ta = el('textarea', {'hx-get': '/frag/preview', 'hx-trigger': 'input changed delay:400ms, load'});
  const preview = el('div', {id: 'prot-preview'}, [el('p', {class: 'placeholder', text: 'Computing…'})]);
  body.appendChild(ta); body.appendChild(preview);
  const x3 = {status: 0};
  xhrEvent('htmx:beforeRequest', preview, ta, {xhr: x3});           // first load: "initial"
  assert.equal(preview.getAttribute('aria-busy'), 'true');
  assert.equal(ui.state().userRequests, 0);
  xhrEvent('htmx:afterRequest', preview, ta, {xhr: x3});
  assert.equal(preview.getAttribute('aria-busy'), null);
  const x4 = {status: 504};
  xhrEvent('htmx:beforeRequest', preview, ta, {xhr: x4, trigger: 'input'});
  assert.equal(ui.state().userRequests, 1);
  assert.ok(preview.classList.contains('is-refreshing'));
  xhrEvent('htmx:afterRequest', preview, ta, {xhr: x4});            // htmx fires afterRequest first for some failures
  dispatch(ta, new Event('htmx:timeout', {bubbles: true, detail: {xhr: x4, target: preview, elt: ta, requestConfig: {}}}));
  assert.equal(ui.state().userRequests, 0, 'counted down once');
  assert.equal(preview.getAttribute('aria-busy'), null, 'never left busy');
  assert.equal(preview.querySelector('.req-error').getAttribute('role'), 'alert');
  assert.match(preview.querySelector('.req-error').textContent, /no answer within 30 s/);

  // never refresh over a field being typed in, nor under a page that is leaving
  const input = el('input', {type: 'text', name: 'code'});
  tile.appendChild(input);
  input.focus();
  assert.equal(xhrEvent('htmx:beforeRequest', tile, tile, {xhr: {}, trigger: 'sse:tick'}).defaultPrevented, true);
  doc.activeElement = body;
  const {f, btn} = opForm('Drain');
  tile.appendChild(f);
  submit(f, btn); advance(0);
  assert.equal(xhrEvent('htmx:beforeRequest', tile, tile, {xhr: {}, trigger: 'sse:tick'}).defaultPrevented, true,
               'a refresh would bring the busy button back enabled');
}

// ---------------------------------------------------------------- the live stream indicator
{
  const {body, ui} = page();
  const live = doc.getElementById('live');
  dispatch(body, new Event('htmx:sseOpen', {bubbles: true, detail: {}}));
  assert.equal(live.getAttribute('data-state'), 'live');
  assert.equal(live.querySelector('.live-text').textContent, 'Live');
  advance(100);
  assert.equal(announced(), '', 'connecting at page load is not announced');
  // a short blip stays quiet
  dispatch(body, new Event('htmx:sseError', {bubbles: true, detail: {}}));
  advance(1000);
  dispatch(body, new Event('htmx:sseOpen', {bubbles: true, detail: {}}));
  advance(3000);
  assert.equal(live.getAttribute('data-state'), 'live');
  assert.equal(body.classList.contains('stale'), false);
  // a real drop: reconnecting after 2 s, offline after 30 s more, then back
  dispatch(body, new Event('htmx:sseError', {bubbles: true, detail: {}}));
  advance(2100);
  assert.equal(live.getAttribute('data-state'), 'reconnecting');
  assert.equal(body.classList.contains('stale'), true, 'controls are held while data may be stale');
  advance(100);
  assert.equal(announced(), 'Live updates lost. Reconnecting.');
  advance(32000);
  assert.equal(live.getAttribute('data-state'), 'offline');
  assert.match(doc.getElementById('stale-msg').textContent, /Offline/);
  const hb = {built_at: clock / 1000 - 3, server_boot_id: 'b1', coordinator_ok: true};
  dispatch(body, new Event('htmx:sseMessage', {bubbles: true, detail: {type: 'heartbeat', data: JSON.stringify(hb)}}));
  assert.equal(live.getAttribute('data-state'), 'live');
  assert.equal(body.classList.contains('stale'), false);
  advance(100);
  assert.equal(announced(), 'Live updates resumed.');
  // missed heartbeats alone also count
  advance(16000);
  assert.equal(live.getAttribute('data-state'), 'reconnecting');
  // the coordinator down while the stream is fine: stale, with its own message
  dispatch(body, new Event('htmx:sseMessage', {bubbles: true, detail: {type: 'heartbeat', data: JSON.stringify({...hb, coordinator_ok: false})}}));
  assert.equal(live.getAttribute('data-state'), 'live');
  assert.equal(body.classList.contains('stale'), true);
  assert.match(doc.getElementById('stale-msg').textContent, /coordinator is unreachable/);
  // a page being left closes its stream: not an outage
  dispatch(body, new Event('htmx:sseMessage', {bubbles: true, detail: {type: 'heartbeat', data: JSON.stringify(hb)}}));
  dispatch(win, new Event('pagehide'));
  dispatch(body, new Event('htmx:sseError', {bubbles: true, detail: {}}));
  advance(5000);
  assert.equal(live.getAttribute('data-state'), 'live');
  // a new server build reloads (with the progress bar)
  dispatch(win, Object.assign(new Event('pageshow'), {persisted: false}));
  dispatch(body, new Event('htmx:sseMessage', {bubbles: true, detail: {type: 'heartbeat', data: JSON.stringify({...hb, server_boot_id: 'b2'})}}));
  assert.equal(win.reloaded, true);
  assert.equal(ui.state().navigating, true);
}

// ---------------------------------------------------------------- the login page: no stream, no staleness
{
  const {body, ui} = page({live: false});
  advance(60000);
  assert.equal(body.classList.contains('stale'), false, 'a page without a stream never greys out');
  const {f, btn} = opForm('Sign in');
  f.setAttribute('action', '/login');
  body.appendChild(f);
  submit(f, btn); advance(0);
  assert.equal(btn.querySelector('.busy-label').textContent, 'Signing in…');
  assert.equal(ui.state().busy, 1);
}
console.log('console UI: ok');
