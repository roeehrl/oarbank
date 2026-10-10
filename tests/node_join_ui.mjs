// Exercise the join window's shipped script without a browser, network or a real node: a small DOM fake, a scripted
// fetch and manual timers. JOIN_UI_CODE and JOIN_UI_PENDING_CODE are fresh OB2 codes made by the Python test (the
// shared vectors expire in the past, which the decoder test below also relies on).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const html = fs.readFileSync(new URL('../deploy/node/join-window.html', import.meta.url), 'utf8');
const source = html.match(/<script nonce="__NONCE__">([\s\S]*)<\/script>/)[1];
const vectors = JSON.parse(fs.readFileSync(new URL('../src/oarbank/contracts/vectors/joincode.json', import.meta.url), 'utf8'));
const FRESH = process.env.JOIN_UI_CODE, PENDING = process.env.JOIN_UI_PENDING_CODE, CONTAINERS = process.env.JOIN_UI_CONTAINERS_CODE;
assert.ok(FRESH && PENDING && CONTAINERS, 'the Python test passes fresh codes');
const plain = v => JSON.parse(JSON.stringify(v));
const flush = async () => { for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve)); };

function tagOf(id) { return (html.match(new RegExp(`<[^>]*\\bid="${id}"[^>]*>`)) || [''])[0]; }

function page({state, routes = {}, token = 'synthetic'}) {
  const registry = new Map();
  let focused = null;
  function element(id) {
    const tag = tagOf(id);
    const el = {
      id, hidden: /\shidden[\s>]/.test(tag), checked: /\schecked[\s>]/.test(tag), textContent: '', value: '', className: '',
      children: [], attrs: {}, listeners: {},
      focus() { focused = this.id; }, select() {}, setAttribute(k, v) { this.attrs[k] = v; },
      addEventListener(name, callback) { this.listeners[name] = callback; },
      appendChild(child) { this.children.push(child); if (child.id) registry.set(child.id, child); return child; },
      replaceChildren(...kids) {
        for (const old of this.children) if (old.id && registry.get(old.id) === old) registry.delete(old.id);
        this.children = [];
        for (const kid of kids) this.appendChild(kid);
      },
      get text() { return this.children.length ? this.children.map(c => c.text).join(' ') : this.textContent; },
    };
    return el;
  }
  const node = id => {
    if (!registry.has(id)) { if (!tagOf(id)) return null; registry.set(id, element(id)); }
    return registry.get(id);
  };
  const requests = [], timers = new Map(), clipboard = {text: null, readable: 'pasted ' + FRESH};
  let nextTimer = 1;
  const reply = async (path, body) => {
    const route = routes[path];
    if (path === '/state') return typeof state === 'function' ? state() : state;
    if (path === '/ping' || path === '/close') return {ok: true};
    if (!route) throw Object.assign(new Error(`unexpected ${path}`), {status: 500});
    return typeof route === 'function' ? route(body) : route;
  };
  const context = vm.createContext({
    document: {getElementById: node, createElement: () => element('')},
    location: {hash: token ? '#' + token : ''},
    navigator: {clipboard: {readText: async () => clipboard.readable, writeText: async text => { clipboard.text = text; }}},
    window: {close() {}},
    btoa, TextDecoder, console,
    setTimeout: (fn, ms) => { const id = nextTimer++; timers.set(id, fn); return id; },
    clearTimeout: id => timers.delete(id),
    setInterval: () => 0,
    clearInterval: () => {},
    fetch: async (path, request) => {
      const body = JSON.parse(request.body);
      assert.equal(request.headers['X-Oarbank-Join'], token);
      requests.push({path, body});
      try {
        const data = await reply(path, body);
        return {ok: true, json: async () => data};
      } catch (e) {
        return {ok: false, json: async () => ({error: e.message, code: e.code})};
      }
    },
  });
  vm.runInContext(source, context);
  return {
    context, node, requests, clipboard, get focused() { return focused; },
    visible: () => ['loading', 'join-screen', 'managed-screen', 'confirm-screen', 'progress-screen', 'waiting-screen',
                    'ready-screen', 'status-screen', 'closed-screen'].filter(id => !node(id).hidden),
    paths: () => requests.map(r => r.path).filter(p => p !== '/ping'),
    async tick() { const due = [...timers.values()]; timers.clear(); for (const fn of due) await fn(); await flush(); },
    async type(text) { node('code').value = text; node('code').listeners.input(); await flush(); },
    async click(id) { await node(id).listeners.click(); await flush(); },
    async submit() { await node('join-form').listeners.submit({preventDefault() {}}); await flush(); },
  };
}

const MAC = {platform: 'macos', scopes: ['system', 'personal'], status: {system: null, personal: null},
             policy: {allow_user_join: true, managed_by: null}, prefill: null, job: null};
const CHECK_OK = {rows: [{row: 'code', ok: true, detail: 'coordinator coord.example.net:7443'},
                         {row: 'dns', ok: true, detail: 'coord.example.net -> 192.0.2.7'}],
                  result: {ok: true, exit: 0, detail: {message: 'All checks passed.'}}};

// ---------------------------------------------------------------- the decoder, against the shared vectors
{
  const p = page({state: MAC});
  await flush();
  const OB2 = p.context.OB2;
  for (const c of vectors.codes) {
    const d = plain(OB2.decode(c.text));
    assert.deepEqual([d.flags, d.expires_at, d.cik, d.pins, d.urls, d.id], [c.flags, c.expires_at, c.cik, c.pins, c.urls, c.id]);
    assert.equal(d.fingerprint, c.pins[0].slice(0, 16));
    assert.equal(d.secret, undefined, 'the page never keeps the secret');
  }
  for (const e of vectors.equivalent) assert.deepEqual(plain(OB2.decode(e.text)), plain(OB2.decode(vectors.codes[e.same_as].text)));
  for (const e of vectors.invalid) assert.throws(() => OB2.decode(e.text), err => err.code === 'E_CODE_FORMAT', e.why);
  assert.throws(() => OB2.check(vectors.codes[0].text, vectors.codes[0].expires_at + 5), err => err.code === 'E_CODE_EXPIRED');
  assert.equal(OB2.crc32(new TextEncoder().encode('123456789')), 0xCBF43926);
  const fresh = OB2.check(FRESH, Date.now() / 1000);
  assert.match(OB2.summary(fresh, Date.now() / 1000), /^coord\.example\.net:7443 · expires in (59|60) minutes · approved at once$/);
  assert.match(OB2.summary(OB2.decode(PENDING), Date.now() / 1000), /needs approval$/);
}

// ---------------------------------------------------------------- typed code: check, join, approval, ready
{
  let progress = 0, joined = false;
  const p = page({
    state: () => joined ? {...MAC, status: {system: {state: 'connected', coordinator: 'https://coord.example.net:7443', name: 'build-07'}, personal: null}} : MAC,
    routes: {
      '/check': CHECK_OK,
      '/join': {started: true, elevated: true, scope: 'system', started_at: 1},
      '/progress': () => (++progress === 1
        ? {kind: 'join', lines: [{type: 'row', row: 'tls', ok: true, detail: 'matches the code'},
                                 {type: 'state', status: {state: 'joining', coordinator: 'https://coord.example.net:7443'}}],
           offset: 120, done: false}
        : {kind: 'join', lines: [{type: 'result', ok: true, exit: 0, detail: {staged: true}}], offset: 200, done: true,
           result: {type: 'result', ok: true, exit: 0, detail: {staged: true}}, cancelled: false, fresh: true, started_at: Date.now() / 1000,
           status: {state: 'pending', coordinator: 'https://coord.example.net:7443', key_fingerprint: 'sha256:1234'}}),
    },
  });
  await flush();
  assert.deepEqual(p.visible(), ['join-screen']);
  assert.equal(p.node('scope-row').hidden, false);
  assert.equal(p.node('containers-row').hidden, true);
  // Join is never disabled: an empty or broken code gets an inline message and nothing is sent
  await p.submit();
  assert.equal(p.node('code-error').textContent, 'Paste the join code first.');
  assert.equal(p.focused, 'code');
  await p.type('OB2-NOTACODE');
  assert.equal(p.node('summary').className, 'summary bad');
  await p.submit();
  assert.match(p.node('code-error').textContent, /incomplete|mistyped|not in it/);
  assert.deepEqual(p.paths(), ['/state']);
  // Paste reads the clipboard only on click
  await p.click('paste');
  assert.equal(p.node('code').value, 'pasted ' + FRESH);
  assert.equal(p.node('summary').className, 'summary bad');
  await p.type(FRESH);
  assert.equal(p.node('summary').className, 'summary good');
  assert.match(p.node('summary').textContent, /coord\.example\.net:7443 · expires in/);
  assert.equal(p.node('scope-system').checked, true, 'the code suggests the system service');
  p.node('name').value = 'bad name';
  await p.submit();
  assert.match(p.node('name-error').textContent, /letters, digits/);
  p.node('name').value = 'build-07';
  await p.submit();
  assert.deepEqual(p.paths(), ['/state', '/check', '/join', '/progress']);
  assert.deepEqual(plain(p.requests[1].body), {code: FRESH});
  assert.deepEqual(plain(p.requests[2].body), {code: FRESH, scope: 'system', containers: false, name: 'build-07'});
  assert.deepEqual(p.visible(), ['progress-screen']);
  assert.match(p.node('progress-text').textContent, /Joining https:\/\/coord\.example\.net:7443/);
  const rows = p.node('rows').children;
  assert.deepEqual(rows.map(r => r.className), ['ok', 'ok', 'ok']);
  assert.match(rows[2].text, /Secure connection: passed matches the code/);
  await p.tick();
  assert.deepEqual(p.visible(), ['waiting-screen']);
  assert.equal(p.node('wait-key').textContent, 'sha256:1234');
  assert.equal(p.node('wait-code-row').hidden, true);
  joined = true;
  await p.tick();
  assert.deepEqual(p.visible(), ['ready-screen']);
  assert.equal(p.node('ready-text').textContent, 'This machine has joined https://coord.example.net:7443 as build-07.');
}

// ---------------------------------------------------------------- a code that arrived by link is confirmed first
{
  const p = page({state: {...MAC, prefill: {code: FRESH, source: 'link'}}, routes: {'/check': {rows: [], result: {ok: false, code: 'E_TCP', exit: 6, message: 'No answer.'}}}});
  await flush();
  assert.deepEqual(p.visible(), ['confirm-screen']);
  assert.equal(p.node('confirm-host').textContent, 'https://coord.example.net:7443');
  assert.equal(p.node('confirm-fp').textContent, 'abababababababab');
  assert.equal(p.node('confirm-approval').textContent, 'Joins at once');
  await p.click('confirm-no');
  assert.deepEqual(p.visible(), ['join-screen']);
  assert.equal(p.node('code').value, '');
  assert.deepEqual(p.paths(), ['/state']);

  const q = page({state: {...MAC, prefill: {code: FRESH, source: 'file'}}, routes: {'/check': {rows: [
    {row: 'code', ok: true, detail: 'coordinator coord.example.net:7443'}, {row: 'tcp', ok: false, detail: 'no answer on port 7443'}],
    result: {ok: false, code: 'E_TCP', exit: 6, message: 'No answer on port 7443.'}}}});
  await flush();
  assert.deepEqual(q.visible(), ['confirm-screen']);
  await q.click('confirm-yes');
  assert.deepEqual(q.visible(), ['join-screen']);
  assert.equal(q.node('code').value, FRESH);
  await q.submit();
  assert.deepEqual(q.paths(), ['/state', '/check']);
  // the failure: rows, plain message, its code, Retry, Copy diagnostics without the code
  assert.equal(q.node('failure').hidden, false);
  assert.equal(q.node('failure-code').textContent, 'E_TCP');
  assert.equal(q.node('failure-message').textContent, 'No answer on port 7443.');
  assert.match(q.node('failure-hint').textContent, /firewall/);
  assert.deepEqual(q.node('rows').children.map(r => r.className), ['ok', 'fail']);
  await q.click('copy-diag');
  const report = q.clipboard.text;
  assert.match(report, /Fingerprint: abababababababab/);
  assert.match(report, /FAIL tcp: no answer on port 7443/);
  assert.match(report, /Result: E_TCP/);
  assert.ok(!report.includes(FRESH) && !report.includes(FRESH.replace(/-/g, '').slice(4, 40)), 'diagnostics never hold the code');
  await q.click('retry');
  assert.deepEqual(q.paths(), ['/state', '/check', '/check']);
  await q.click('back');
  assert.deepEqual(q.visible(), ['join-screen']);

  // Join itself also refuses an unconfirmed link or file code (not only the first screen)
  const r = page({state: MAC});
  await flush();
  await r.type(FRESH);
  r.context.JoinWindow.source = 'link';
  await r.submit();
  assert.deepEqual(r.visible(), ['confirm-screen']);
  assert.deepEqual(r.paths(), ['/state']);
}

// ---------------------------------------------------------------- a dismissed administrator prompt
{
  const p = page({state: MAC, routes: {'/check': CHECK_OK, '/join': {started: true, elevated: true},
    '/progress': {kind: 'join', lines: [], offset: 0, done: true, result: null, cancelled: true, exit: 1}}});
  await flush();
  await p.type(FRESH);
  await p.submit();
  assert.equal(p.node('failure-code').textContent, 'E_CANCELLED');
  assert.match(p.node('failure-message').textContent, /Nothing changed/);
}

// ---------------------------------------------------------------- joined: status, Leave, managed machines
{
  let left = false;
  const joined = {state: 'connected', coordinator: 'https://coord.example.net:7443', node_id: 'n_1', name: 'lab'};
  const p = page({state: () => ({...MAC, status: {system: left ? {state: 'unjoined'} : joined, personal: null}}),
                  routes: {'/leave': {started: true, elevated: true, kind: 'leave'},
                           '/progress': () => { left = true; return {kind: 'leave', lines: [], offset: 0, done: true, cancelled: false,
                             result: {type: 'result', ok: true, exit: 0, detail: {message: 'left'}}}; }}});
  await flush();
  assert.deepEqual(p.visible(), ['status-screen']);
  assert.equal(p.node('st-state').textContent, 'Connected');
  assert.equal(p.node('st-name').textContent, 'lab');
  assert.equal(p.node('st-scope').textContent, 'System service');
  assert.equal(p.node('leave').hidden, false);
  await p.click('leave');
  assert.equal(p.node('leave-confirm').hidden, false);
  assert.deepEqual(p.paths(), ['/state'], 'Leave asks first');
  await p.click('leave-yes');
  assert.deepEqual(p.paths(), ['/state', '/leave', '/progress', '/state']);
  assert.deepEqual(p.visible(), ['join-screen']);
  assert.equal(p.node('notice').textContent, 'This machine left its fleet.');

  const managed = {...MAC, policy: {allow_user_join: false, managed_by: 'Example Corp'}};
  const q = page({state: {...managed, status: {system: joined, personal: null}}});
  await flush();
  assert.deepEqual(q.visible(), ['status-screen']);
  assert.equal(q.node('leave').hidden, true);
  assert.equal(q.node('st-managed').textContent, 'Example Corp');
  assert.equal(q.node('notice').textContent, 'Managed by Example Corp');
  const r = page({state: managed});
  await flush();
  assert.deepEqual(r.visible(), ['managed-screen']);
}

// ---------------------------------------------------------------- Windows options, an earlier error, no link
{
  const p = page({state: {...MAC, platform: 'windows', scopes: ['system'], status: {system: {state: 'error',
    error: {code: 'E_APPROVAL_DENIED', message: 'The owner declined this machine.'}}}},
    routes: {'/check': CHECK_OK, '/join': {started: true, elevated: true}, '/progress': {kind: 'join', lines: [], offset: 0, done: false}}});
  await flush();
  assert.deepEqual(p.visible(), ['join-screen']);
  assert.equal(p.node('scope-row').hidden, true);
  assert.equal(p.node('containers-row').hidden, false);
  assert.match(p.node('status-error').textContent, /declined this machine.*E_APPROVAL_DENIED/);
  await p.type(CONTAINERS);
  assert.equal(p.node('containers').checked, true, 'the code suggests container jobs');
  await p.submit();
  assert.deepEqual(plain(p.requests.find(r => r.path === '/join').body), {code: CONTAINERS, scope: 'system', containers: true, name: ''});
  assert.match(p.node('progress-text').textContent, /administrator prompt/);

  const q = page({state: MAC, token: ''});
  await flush();
  assert.deepEqual(q.requests, []);
  assert.match(q.node('error').textContent, /Open Oarbank Node/);
}
// ---------------------------------------------------------------- work in progress shows, and always stops
{
  let release;
  const held = new Promise(resolve => { release = resolve; });
  const p = page({state: MAC, routes: {'/check': async () => { await held; return {rows: [{row: 'tcp', ok: false, detail: 'no answer'}],
    result: {ok: false, code: 'E_TCP', exit: 6, message: 'No answer.'}}; }}});
  await flush();
  assert.match(tagOf('loading-text'), /class="working"/, 'loading has a spinner beside its words');
  await p.type(FRESH);
  const submitted = p.submit();
  await flush();
  assert.deepEqual(p.visible(), ['progress-screen']);
  assert.equal(p.node('progress-text').className, 'working', 'a spinner while the checks run');
  assert.equal(p.node('rows').attrs['aria-busy'], 'true');
  assert.equal(p.node('progress-elapsed').hidden, true, 'no elapsed time in the first 10 s');
  release();
  await submitted; await flush();
  assert.equal(p.node('failure').hidden, false);
  assert.equal(p.node('progress-text').className, '', 'the spinner stops on failure');
  assert.equal(p.node('rows').attrs['aria-busy'], 'false');
  assert.equal(p.context.elapsedText(9), '');
  assert.equal(p.context.elapsedText(25), 'Running for 25 seconds');
  assert.equal(p.context.elapsedText(125), 'Running for 2 min 5 s');
}
console.log('join window UI: ok');
