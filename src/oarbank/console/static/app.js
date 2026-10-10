// oarbank-console behaviour. Everything binds through data- attributes: no inline script (strict CSP).
// Loading, busy and connection states follow docs/design/console-loading-states.md.
(function () {
  "use strict";
  var doc = document, body = doc.body;
  var DELAY_MS = 300;            // indicators appear only after this (CSS animation-delay): quick answers never flicker
  var LONG_MS = 10000;           // past this a busy control shows its elapsed time (NN/g: the 10 s limit)
  var NAV_GIVE_UP_MS = 20000;    // a link navigation still pending after this is a download or a stopped load
  var live = body.hasAttribute("sse-connect");
  var now = function () { return Date.now(); };

  // CSRF: every POST form and every htmx request carries the session's token (meta csrf-token).
  function csrfToken() {
    var m = doc.querySelector('meta[name="csrf-token"]');
    return m ? m.content : "";
  }
  doc.addEventListener("htmx:configRequest", function (ev) {
    ev.detail.headers["X-CSRF-Token"] = csrfToken();
  });

  // ---------------------------------------------------------------- one polite live region, for transitions only
  var announcer = doc.getElementById("announcer");
  if (!announcer) {
    announcer = doc.createElement("div");
    announcer.id = "announcer";
    announcer.className = "sr-only";
    announcer.setAttribute("role", "status");
    announcer.setAttribute("aria-live", "polite");
    body.appendChild(announcer);
  }
  function announce(text) {
    announcer.textContent = "";
    setTimeout(function () { announcer.textContent = text; }, 60);   // a repeated message is spoken again
  }

  function seconds(ms) {
    var s = Math.max(0, Math.round(ms / 1000));
    if (s < 60) return s + " s";
    return Math.floor(s / 60) + " min " + (s % 60) + " s";
  }

  // ---------------------------------------------------------------- the top progress bar
  // Driven by full-page navigations (links, form posts, reloads) and by htmx requests the user started. CSS reveals it
  // after DELAY_MS and trickles it toward 92%; it completes visibly only if it was already showing.
  var bar = null, navigating = false, navTimer = null, userRequests = 0, barSince = 0, uploading = 0;
  function barEl() {
    if (!bar) {
      bar = doc.createElement("div");
      bar.className = "topbar";
      bar.setAttribute("aria-hidden", "true");
      bar.appendChild(doc.createElement("i"));
      body.insertBefore(bar, body.firstChild);
    }
    return bar;
  }
  function barSync() {
    var b = barEl(), on = navigating || userRequests > 0, active = b.classList.contains("is-active");
    if (on && !active) {
      b.classList.remove("is-done");
      b.classList.add("is-active");
      barSince = now();
    } else if (!on && active) {
      b.classList.remove("is-active");
      if (now() - barSince >= DELAY_MS) {
        b.classList.add("is-done");
        setTimeout(function () { b.classList.remove("is-done"); }, 600);
      }
    }
  }
  function startNav(giveUpMs) {
    navigating = true;
    clearTimeout(navTimer);
    if (giveUpMs) navTimer = setTimeout(stopNav, giveUpMs);
    barSync();
  }
  function stopNav() {
    navigating = false;
    clearTimeout(navTimer);
    barSync();
  }

  // ---------------------------------------------------------------- busy buttons
  // The verb on the button in -ing form ("Revoke" -> "Revoking…"); a template can say exactly with data-busy-label.
  var GERUND = {Set: "Setting", Stop: "Stopping", Run: "Running", Get: "Getting", Log: "Logging", Plan: "Planning",
                Pin: "Pinning", Unpin: "Unpinning", Drop: "Dropping", Map: "Mapping", Begin: "Beginning"};
  var VERBS = new RegExp("^(Apply|Approve|Decline|Revoke|Pause|Resume|Sign|Promote|Install|Enable|Disable|Save|Create|" +
    "Delete|Remove|Upload|Cancel|Restart|Retry|Set|Add|Drain|Filter|Stop|Start|Run|Update|Reset|Rotate|Restore|Retire|" +
    "Register|Import|Export|Uninstall|Upgrade|Pin|Unpin|Clear|Change|Send|Test|Turn|Verify|Mark|Move|Map|Withdraw|" +
    "Confirm|Reject|Admit|Accept|Allow|Block|Rename|Make|Generate|Issue|Refresh|Recheck|Check|Rebuild|Build|Deploy|" +
    "Roll|Kill|Requeue|Release|Unblock|Purge|Prune|Open|Show|Begin|Finish|Attach|Detach|Grant|Lock|Unlock)\\b");
  function busyLabel(btn) {
    if (btn.dataset && btn.dataset.busyLabel) return btn.dataset.busyLabel;
    var text = (btn.textContent || "").replace(/\s+/g, " ").trim();
    if (/^Review\b/.test(text)) return "Preparing review…";
    var m = VERBS.exec(text);
    if (!m) return "Working…";
    var v = m[1], g = GERUND[v] || (/[^e]e$/.test(v) ? v.slice(0, -1) + "ing" : v + "ing");
    var particle = /^\S+ (in|out|on|off|up|back)\b/.exec(text);      // "Sign out" -> "Signing out…"
    return g + (particle ? " " + particle[1] : "") + "…";
  }

  var busy = [];                 // [{btn, form, since, html, minWidth, disabled, label, said}]
  var ticker = null;
  function tick() {
    var t = now();
    busy.forEach(function (b) {
      var el = b.btn.querySelector(".busy-elapsed"), ms = t - b.since;
      if (!el || ms < LONG_MS) return;
      el.textContent = seconds(ms);
      if (!b.said) { b.said = true; announce(b.label.replace(/…$/, "") + ": still working, " + seconds(ms) + "."); }
    });
    if (!busy.length) { clearInterval(ticker); ticker = null; }
  }
  function setBusy(btn, form, label) {
    if (!btn || btn.dataset.busy) return null;
    var rec = {btn: btn, form: form, since: now(), html: btn.innerHTML, minWidth: btn.style.minWidth,
               disabled: btn.disabled, label: label || busyLabel(btn), said: false};
    var w = btn.getBoundingClientRect ? btn.getBoundingClientRect().width : 0;
    if (w) btn.style.minWidth = Math.ceil(w) + "px";             // never narrower than it was: no layout jump
    btn.dataset.busy = "1";
    btn.classList.add("is-busy");
    btn.setAttribute("aria-disabled", "true");
    var spin = doc.createElement("span");
    spin.className = "spin";
    spin.setAttribute("aria-hidden", "true");
    var text = doc.createElement("span");
    text.className = "busy-label";
    text.textContent = rec.label;
    var el = doc.createElement("span");
    el.className = "busy-elapsed";
    btn.textContent = "";
    btn.appendChild(spin);
    btn.appendChild(text);
    btn.appendChild(el);
    btn.disabled = true;
    busy.push(rec);
    if (!ticker) ticker = setInterval(tick, 1000);
    return rec;
  }
  function relabel(btn, text) {
    var t = btn && btn.querySelector(".busy-label");
    if (t) t.textContent = text;
  }
  function clearBusy(btn) {
    busy = busy.filter(function (b) {
      if (btn && b.btn !== btn) return true;
      b.btn.innerHTML = b.html;
      b.btn.style.minWidth = b.minWidth;
      b.btn.disabled = b.disabled;
      b.btn.removeAttribute("aria-disabled");
      b.btn.classList.remove("is-busy");
      delete b.btn.dataset.busy;
      if (b.form) { delete b.form.dataset.busy; b.form.removeAttribute("aria-busy"); }
      return false;
    });
  }
  // Back to an interactive page: from the back/forward cache, or after a stopped load.
  function resetAll() {
    stopNav();
    clearBusy(null);
    var forms = doc.querySelectorAll("form[data-busy]");
    for (var f = 0; f < forms.length; f++) { delete forms[f].dataset.busy; forms[f].removeAttribute("aria-busy"); }
    var staged = doc.querySelectorAll("input[data-staged]");
    for (var i = 0; i < staged.length; i++) staged[i].parentNode.removeChild(staged[i]);
    var held = doc.querySelectorAll("input[data-stage-held]");
    for (var j = 0; j < held.length; j++) { held[j].disabled = false; delete held[j].dataset.stageHeld; }
    var ups = doc.querySelectorAll(".upload-progress");
    for (var k = 0; k < ups.length; k++) ups[k].hidden = true;
  }
  window.addEventListener("pageshow", function (ev) { if (ev.persisted) resetAll(); });
  doc.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape" && navigating && !uploading) setTimeout(resetAll, 0);   // Escape stops a page load
  });

  // ---------------------------------------------------------------- form submissions
  function submitterOf(ev, f) {
    var s = ev.submitter;
    if (s && s.tagName === "BUTTON") return s;
    var bs = f.querySelectorAll("button");
    for (var i = 0; i < bs.length; i++) if ((bs[i].getAttribute("type") || "submit") === "submit") return bs[i];
    return null;
  }

  // Capture phase: the CSRF field, the double-submit guard, T1 confirmation and the reason prompt run first.
  doc.addEventListener("submit", function (ev) {
    var f = ev.target;
    if (!(f instanceof HTMLFormElement)) return;
    if (f.dataset.busy) { ev.preventDefault(); ev.stopImmediatePropagation(); return; }   // no double submit
    var token = csrfToken();
    if (token && (f.method || "").toLowerCase() === "post" && !f.querySelector('input[name="csrf"]')) {
      var c = doc.createElement("input");
      c.type = "hidden"; c.name = "csrf"; c.value = token;
      f.appendChild(c);
    }
    var again = f.querySelector("input[data-staged]");   // the second pass after an upload: already confirmed
    if (!again && f.dataset.confirm && !window.confirm(f.dataset.confirm)) { ev.preventDefault(); return; }
    if (!again && f.dataset.reason === "prompt") {
      var r = window.prompt("Reason (recorded in the audit log):", "");
      if (r === null) { ev.preventDefault(); return; }
      var inp = f.querySelector('input[name="reason"]');
      if (inp) inp.value = r;
    }
    if (f.dataset.stage && !again && stageUpload(f, submitterOf(ev, f))) ev.preventDefault();   // the file goes first
  }, true);

  // Bubble phase, after every handler had its say: a submission that goes ahead shows its busy state.
  doc.addEventListener("submit", function (ev) {
    var f = ev.target;
    if (!(f instanceof HTMLFormElement) || f.hasAttribute("data-no-busy")) return;
    var btn = submitterOf(ev, f);
    var target = (ev.submitter && ev.submitter.getAttribute("formtarget")) || f.getAttribute("target") || "";
    var newTab = target && target !== "_self";
    var marked = !ev.defaultPrevented && !newTab;
    if (marked) f.dataset.busy = "1";           // at once: a second submit is dropped
    setTimeout(function () {                    // after the form's data set is built (a disabled button is not sent)
      if (ev.defaultPrevented) { if (marked) delete f.dataset.busy; return; }
      if (newTab) {                             // a new tab: this page stays; only hold the button against a double click
        if (btn) { btn.disabled = true; setTimeout(function () { btn.disabled = false; }, 1500); }
        return;
      }
      f.dataset.busy = "1";
      f.setAttribute("aria-busy", "true");
      var rec = setBusy(btn, f);
      if (rec) announce(rec.label);
      startNav(0);                              // a POST may legitimately take minutes: no give-up timer
    }, 0);
  });

  // ---------------------------------------------------------------- link navigations
  doc.addEventListener("click", function (ev) {
    if (ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
    var a = ev.target.closest ? ev.target.closest("a[href]") : null;
    if (!a || a.hasAttribute("download") || a.hasAttribute("data-no-progress")) return;
    if (a.target && a.target !== "_self") return;
    var url;
    try { url = new URL(a.href, window.location.href); } catch (e) { return; }
    if (url.origin !== window.location.origin || !/^https?:$/.test(url.protocol)) return;
    if (url.hash && url.pathname === window.location.pathname && url.search === window.location.search) return;
    setTimeout(function () { if (!ev.defaultPrevented) startNav(NAV_GIVE_UP_MS); }, 0);
  });

  // ---------------------------------------------------------------- uploads with progress (op_form data-stage)
  // The file goes to POST /stage/<op> by XHR (upload progress events); the coordinator stages it and answers its SHA-256,
  // and the form then posts only that (p.sha256), as the CLI does. Without script the form posts the file itself.
  function uploadUI(f) {
    var ui = f.querySelector(".upload-progress");
    if (!ui) {
      ui = doc.createElement("div");
      ui.className = "upload-progress";
      var p = doc.createElement("progress");
      p.max = 100; p.value = 0;
      p.setAttribute("aria-label", "Upload progress");
      var label = doc.createElement("span");
      label.className = "upload-pct";
      var cancel = doc.createElement("button");
      cancel.type = "button"; cancel.className = "upload-cancel"; cancel.textContent = "Cancel upload";
      cancel.setAttribute("data-always", "");
      ui.appendChild(p); ui.appendChild(label); ui.appendChild(cancel);
      f.appendChild(ui);
    }
    ui.hidden = false;
    var prog = ui.querySelector("progress");
    prog.value = 0;
    prog.removeAttribute("aria-valuetext");
    var cancelBtn = ui.querySelector(".upload-cancel");
    cancelBtn.hidden = false;
    return {root: ui, bar: prog, label: ui.querySelector(".upload-pct"), cancel: cancelBtn};
  }
  function mb(n) { return (n / 1048576).toFixed(n < 10485760 ? 1 : 0) + " MB"; }
  function stageUpload(f, btn) {
    var input = f.querySelector('input[type="file"][name="' + f.dataset.stageField + '"]');
    if (!input || input.disabled || !input.files || !input.files.length || !window.XMLHttpRequest) return false;
    var file = input.files[0], ui = uploadUI(f), xhr = new XMLHttpRequest();
    clearError(f);
    f.dataset.busy = "1";
    f.setAttribute("aria-busy", "true");
    setBusy(btn, f, "Uploading…");
    uploading += 1;
    startNav(0);
    announce("Uploading " + file.name + ".");
    ui.label.textContent = "0% of " + mb(file.size);
    var done = function () { uploading = Math.max(0, uploading - 1); };
    var fail = function (msg) {
      done();
      stopNav();
      clearBusy(btn);
      delete f.dataset.busy;
      f.removeAttribute("aria-busy");
      ui.root.hidden = true;
      showError(f, msg, function () { if (f.requestSubmit) f.requestSubmit(btn || undefined); }, true);
    };
    xhr.upload.onprogress = function (e) {
      if (!e.lengthComputable) return;
      var pct = Math.floor(100 * e.loaded / Math.max(e.total, 1));
      ui.bar.value = pct;
      ui.bar.setAttribute("aria-valuetext", pct + "% uploaded");
      ui.label.textContent = pct + "% of " + mb(e.total);
      relabel(btn, "Uploading… " + pct + "%");
    };
    xhr.onload = function () {
      var j = {};
      try { j = JSON.parse(xhr.responseText || "{}"); } catch (e) { j = {}; }
      if (xhr.status !== 200 || !j.sha256) {
        fail("Upload failed" + (j.detail || j.error ? ": " + (j.detail || j.error) : " (HTTP " + xhr.status + ")") + ".");
        return;
      }
      done();
      var h = doc.createElement("input");
      h.type = "hidden"; h.name = "p.sha256"; h.value = j.sha256;
      h.setAttribute("data-staged", "");
      f.appendChild(h);
      input.disabled = true;                    // the bytes are staged: the form sends only their digest
      input.dataset.stageHeld = "1";
      ui.bar.value = 100;
      ui.label.textContent = "Uploaded " + mb(file.size);
      ui.cancel.hidden = true;
      announce("Upload complete.");
      clearBusy(btn);
      delete f.dataset.busy;
      if (f.requestSubmit) f.requestSubmit(btn || undefined);
      else { f.dataset.busy = "1"; setBusy(btn, f); f.submit(); }
    };
    xhr.onerror = function () { fail("Upload failed: the console could not be reached."); };
    xhr.onabort = function () { fail("Upload cancelled."); };
    ui.cancel.onclick = function () { xhr.abort(); };
    xhr.open("POST", f.dataset.stage);
    xhr.setRequestHeader("X-CSRF-Token", csrfToken());
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.send(file);
    return true;
  }

  // ---------------------------------------------------------------- inline errors with Retry
  var errors = new WeakMap();                    // region -> its error note
  function clearError(region) {
    var n = region && errors.get(region);
    if (n && n.parentNode) n.parentNode.removeChild(n);
    if (region) errors.delete(region);
  }
  // loud: role=alert (a request the user started); quiet: role=status, created once and then updated without a repeat.
  function showError(region, message, retry, loud) {
    var n = errors.get(region);
    if (!n || !n.parentNode || !region.contains(n)) {
      n = doc.createElement("div");
      n.className = "req-error";
      n.setAttribute("role", loud ? "alert" : "status");
      var msg = doc.createElement("span");
      msg.className = "req-error-msg";
      n.appendChild(msg);
      if (retry) {
        var b = doc.createElement("button");
        b.type = "button"; b.textContent = "Retry";
        b.setAttribute("data-always", "");
        b.addEventListener("click", function () { clearError(region); retry(); });
        n.appendChild(b);
      }
      region.insertBefore(n, region.firstChild);
      errors.set(region, n);
    }
    n.querySelector(".req-error-msg").textContent = message;
  }

  // ---------------------------------------------------------------- htmx requests
  // A request is the user's when a user event triggered it (or Retry), "initial" when it is an element's first load
  // (hx-trigger load), and background otherwise (sse:tick, sse:resync, every Ns): background requests stay quiet.
  var USER_EVENTS = /^(click|submit|change|input|keyup|keydown|search|paste)$/;
  function kind(d) {
    var t = d.requestConfig && d.requestConfig.triggeringEvent, elt = d.elt;
    if (elt && elt.dataset && elt.dataset.retry) { delete elt.dataset.retry; return "user"; }
    if (t && USER_EVENTS.test(t.type)) return "user";
    if (elt && elt.dataset && !elt.dataset.loaded && /(^|[\s,])load\b/.test(elt.getAttribute("hx-trigger") || "")) return "initial";
    return "background";
  }
  function editing(region) {
    var a = doc.activeElement;
    if (!a || !region.contains(a)) return false;
    return (a.tagName === "INPUT" && !/^(button|submit|reset|checkbox|radio|hidden|file)$/i.test(a.type)) ||
           a.tagName === "TEXTAREA" || a.tagName === "SELECT";
  }
  var inflight = new WeakMap();                  // xhr -> {kind, target, elt, done}
  var deferred = new Map();                      // region -> element whose refresh waited for an edit to end

  doc.addEventListener("htmx:beforeRequest", function (ev) {
    var d = ev.detail, k = kind(d), target = d.target || d.elt;
    if (k === "background") {
      // never refresh under a page that is leaving (its busy button would come back) or over a field being typed in
      if (navigating) { ev.preventDefault(); return; }
      if (target && editing(target)) { deferred.set(target, d.elt); ev.preventDefault(); return; }
    }
    inflight.set(d.xhr, {kind: k, target: target, elt: d.elt, done: false});
    if (k !== "background" && target) {
      target.setAttribute("aria-busy", "true");
      target.classList.add("is-refreshing");
    }
    if (k === "user") { userRequests += 1; barSync(); }
  });
  function finish(d) {
    var r = d && d.xhr && inflight.get(d.xhr);
    if (!r) return null;
    if (r.done) return r;
    r.done = true;
    if (r.kind !== "background" && r.target) {
      r.target.removeAttribute("aria-busy");
      r.target.classList.remove("is-refreshing");
    }
    if (r.kind === "user") { userRequests = Math.max(0, userRequests - 1); barSync(); }
    if (r.elt && r.elt.dataset) r.elt.dataset.loaded = "1";
    return r;
  }
  function retryFor(r, d) {
    var cfg = d.requestConfig || {}, elt = r.elt;
    return function () {
      if (!window.htmx || !elt || !body.contains(elt)) { reload(); return; }
      elt.dataset.retry = "1";
      window.htmx.ajax(cfg.verb ? cfg.verb.toUpperCase() : "GET", cfg.path || elt.getAttribute("hx-get"),
                       {source: elt, target: r.target, swap: elt.getAttribute("hx-swap") || "innerHTML"});
    };
  }
  function failed(d, why) {
    var r = finish(d);
    if (!r || !r.target) return;
    var msg = r.kind === "background"
      ? "Not refreshed at " + new Date().toLocaleTimeString() + " (" + why + "). What you see may be out of date."
      : "Could not update this (" + why + ").";
    showError(r.target, msg, retryFor(r, d), r.kind !== "background");
  }
  doc.addEventListener("htmx:responseError", function (ev) {
    var x = ev.detail.xhr, s = x ? x.status : 0;
    failed(ev.detail, s === 403 ? "the session changed: reload the page" : "the console answered HTTP " + s);
  });
  doc.addEventListener("htmx:sendError", function (ev) { failed(ev.detail, "the console could not be reached"); });
  doc.addEventListener("htmx:timeout", function (ev) { failed(ev.detail, "no answer within 30 s"); });
  doc.addEventListener("htmx:afterRequest", function (ev) { finish(ev.detail); });
  doc.addEventListener("htmx:abort", function (ev) { finish(ev.detail); });

  // A background swap keeps focus on the same control (htmx restores focus only to elements with an id).
  function focusKey(el) {
    var f = el.closest ? el.closest("form") : null;
    if (f) {
      var t = f.querySelector('input[name="target"]');
      return {form: f.getAttribute("action") || "", target: t ? t.value : "", text: (el.textContent || "").trim(), tag: el.tagName};
    }
    if (el.tagName === "A") return {href: el.getAttribute("href") || "", tag: "A"};
    return null;
  }
  function findKey(region, key) {
    if (key.tag === "A") {
      var as = region.querySelectorAll("a");
      for (var i = 0; i < as.length; i++) if ((as[i].getAttribute("href") || "") === key.href) return as[i];
      return null;
    }
    var fs = region.querySelectorAll("form");
    for (var j = 0; j < fs.length; j++) {
      var t = fs[j].querySelector('input[name="target"]');
      if ((fs[j].getAttribute("action") || "") !== key.form || (t ? t.value : "") !== key.target) continue;
      var els = fs[j].querySelectorAll(key.tag.toLowerCase());
      for (var k = 0; k < els.length; k++) if ((els[k].textContent || "").trim() === key.text) return els[k];
      return els[0] || null;
    }
    return null;
  }
  var refocus = new WeakMap();
  doc.addEventListener("htmx:beforeSwap", function (ev) {
    var a = doc.activeElement, target = ev.detail.target;
    if (!target || ev.detail.shouldSwap === false) return;
    clearError(target);
    if (a && a !== body && target.contains(a) && !a.id) {
      var key = focusKey(a);
      if (key) refocus.set(target, key);
    }
  });
  doc.addEventListener("htmx:afterSettle", function (ev) {
    var target = ev.detail.target, key = target && refocus.get(target);
    if (!key) return;
    refocus.delete(target);
    var el = findKey(target, key);
    if (el && el.focus) el.focus({preventScroll: true});
  });
  doc.addEventListener("focusout", function (ev) {
    deferred.forEach(function (elt, region) {
      if (!region.contains(ev.target)) return;
      setTimeout(function () {
        if (editing(region) || !window.htmx) return;
        deferred.delete(region);
        if (body.contains(elt)) window.htmx.trigger(elt, "sse:resync");       // the refresh that waited for the edit
      }, 0);
    });
  });

  // ---------------------------------------------------------------- caps table, protection picker, copy, chart
  // Caps table: a row's number input is enabled only while its checkbox is on.
  doc.addEventListener("change", function (ev) {
    var t = ev.target;
    if (t.matches && t.matches("input[data-toggles-row]")) {
      var n = t.closest("tr").querySelector("input[type=number]");
      if (n) n.disabled = !t.checked;
    }
  });

  // Protection editor: the process picker appends a suggested rule to the JSON editor, then re-runs the preview.
  doc.addEventListener("click", function (ev) {
    var b = ev.target.closest ? ev.target.closest("button[data-add-rule]") : null;
    if (!b) return;
    var ta = doc.getElementById(b.dataset.target);
    if (!ta) return;
    var cfg;
    try { cfg = JSON.parse(ta.value || "{}"); } catch (e) { window.alert("The editor holds invalid JSON; fix it first."); return; }
    cfg.schema = cfg.schema || 1;
    cfg.rule = cfg.rule || [];
    cfg.rule.push(JSON.parse(b.dataset.addRule));
    ta.value = JSON.stringify(cfg, null, 2);
    ta.dispatchEvent(new Event("input", {bubbles: true}));
    ta.scrollIntoView({block: "center"});
  });

  // Copy buttons (the Add machine result): data-copy names the element whose text is copied. The Clipboard API needs a
  // secure context (https or localhost); a console reached over plain http on a tailnet falls back to selecting the
  // text and the legacy copy command, and if that fails too the text stays selected for Cmd/Ctrl+C.
  function selectText(el) {
    var range = doc.createRange();
    range.selectNodeContents(el);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
  function copied(b, ok) {
    var was = b.dataset.label || b.textContent;
    b.dataset.label = was;
    if (!b.style.minWidth && b.getBoundingClientRect) b.style.minWidth = Math.ceil(b.getBoundingClientRect().width) + "px";
    b.textContent = ok ? "Copied" : "Press Cmd/Ctrl+C";
    announce(ok ? "Copied to the clipboard." : "Not copied: the text is selected; press Command or Control and C.");
    setTimeout(function () { b.textContent = was; }, 1800);
  }
  doc.addEventListener("click", function (ev) {
    var b = ev.target.closest ? ev.target.closest("button[data-copy]") : null;
    if (!b) return;
    var el = doc.getElementById(b.dataset.copy);
    if (!el) return;
    function legacy() {
      selectText(el);
      var ok = false;
      try { ok = doc.execCommand("copy"); } catch (e) { ok = false; }
      copied(b, ok);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(el.textContent).then(function () { copied(b, true); }, legacy);
      return;
    }
    legacy();
  });

  // Node chart (uPlot) from a data attribute.
  function chart() {
    var el = doc.getElementById("chart");
    if (!el || !window.uPlot || el.dataset.drawn) return;
    var S = JSON.parse(el.dataset.series || "{}");
    el.dataset.drawn = "1";
    if (!S.t || S.t.length < 2) { el.textContent = "no samples yet"; return; }
    new uPlot({width: Math.min(doc.querySelector("main").clientWidth - 40, 1300), height: 220,
      series: [{}, {label: "mem GB", stroke: "#12a150"}, {label: "running", stroke: "#d68a00"},
               {label: "slots", stroke: "#98a2b3", dash: [4, 4]}, {label: "reserved GB", stroke: "#d92d20"}],
      axes: [{}, {}]}, [S.t, S.mem, S.busy, S.slots, S.reserved], el);
  }

  // ---------------------------------------------------------------- the live stream: connection state and staleness
  // The header says Live, Reconnecting or Offline. Missed heartbeats (~15 s), a stream down for 2 s or an unreachable
  // coordinator grey out live tiles and disable every control except the fleet pause, and the stale banner gives the
  // data's age; a new server_boot_id reloads the page (templates and assets changed). Only transitions are announced.
  var conn = {state: "connecting", lastBeat: now(), builtAt: null, coordinatorOk: true, lostAt: 0, leaving: false, errTimer: null};
  var CONN_TEXT = {connecting: "Connecting…", live: "Live", reconnecting: "Reconnecting…", offline: "Offline"};
  var CONN_TITLE = {connecting: "Connecting to live updates", live: "Live updates are on",
                    reconnecting: "Live updates paused: reconnecting",
                    offline: "Live updates stopped: this browser is offline or the console cannot be reached"};
  function setConn(state) {
    if (state === conn.state) return;
    var was = conn.state;
    conn.state = state;
    if (state !== "live" && !conn.lostAt) conn.lostAt = now();
    if (state === "live") conn.lostAt = 0;
    var el = doc.getElementById("live");
    if (el) {
      el.setAttribute("data-state", state);
      var t = el.querySelector(".live-text");
      if (t) t.textContent = CONN_TEXT[state];
      el.title = CONN_TITLE[state];
    }
    if (state === "reconnecting" && was === "live") announce("Live updates lost. Reconnecting.");
    else if (state === "offline") announce("Offline. Live updates stopped; the page may be out of date.");
    else if (state === "live" && (was === "reconnecting" || was === "offline")) announce("Live updates resumed.");
    paintStale();
  }
  function paintStale() {
    var stale = conn.state === "reconnecting" || conn.state === "offline" || conn.coordinatorOk === false;
    body.classList.toggle("stale", stale);
    var msg = doc.getElementById("stale-msg");
    if (msg) msg.textContent = conn.coordinatorOk === false && conn.state === "live"
      ? "The coordinator is unreachable; data may be out of date"
      : conn.state === "offline" ? "Offline: live updates stopped; data may be out of date"
      : "Live updates paused, reconnecting; data may be out of date";
    var s = doc.getElementById("stale-age");
    if (s && conn.builtAt) s.textContent = new Date(conn.builtAt * 1000).toLocaleTimeString() + " (" + seconds(now() - conn.builtAt * 1000) + " ago)";
  }
  function reload() { startNav(0); window.location.reload(); }
  if (live) {
    window.addEventListener("pagehide", function () { conn.leaving = true; });
    window.addEventListener("pageshow", function () { conn.leaving = false; });
    body.addEventListener("htmx:sseOpen", function () { clearTimeout(conn.errTimer); conn.lastBeat = now(); setConn("live"); });
    body.addEventListener("htmx:sseError", function () {
      if (conn.leaving || navigating) return;          // a page being left closes its stream; that is not an outage
      clearTimeout(conn.errTimer);
      conn.errTimer = setTimeout(function () {         // EventSource retries in 3 s: a blip shorter than 2 s stays quiet
        if (!conn.leaving && !navigating) setConn(navigator.onLine === false ? "offline" : "reconnecting");
      }, 2000);
    });
    body.addEventListener("htmx:sseMessage", function (ev) {
      if (ev.detail.type !== "heartbeat") return;
      try {
        var hb = JSON.parse(ev.detail.data);
        conn.lastBeat = now();
        conn.builtAt = hb.built_at;
        var boot = body.dataset.boot;
        if (boot && hb.server_boot_id && hb.server_boot_id !== boot) { reload(); return; }
        conn.coordinatorOk = hb.coordinator_ok !== false;
        var asOf = doc.getElementById("as-of");
        if (asOf && hb.built_at) asOf.textContent = new Date(hb.built_at * 1000).toLocaleTimeString([], {hour12: false});
        clearTimeout(conn.errTimer);
        if (conn.state !== "live") setConn("live"); else paintStale();
      } catch (e) { /* ignore */ }
    });
    window.addEventListener("offline", function () { if (!conn.leaving) setConn("offline"); });
    window.addEventListener("online", function () { if (conn.state === "offline") setConn("reconnecting"); });
    setInterval(function () {
      if (navigating || conn.leaving) return;
      if (now() - conn.lastBeat > 15000 && conn.state === "live") setConn("reconnecting");
      if (conn.state === "reconnecting" && conn.lostAt && now() - conn.lostAt > 30000) setConn("offline");
      if (conn.state !== "live" || conn.coordinatorOk === false) paintStale();
    }, 2000);
    // A tab that was hidden for over a minute resyncs when it comes back (htmx 2 has no pauseOnBackground).
    var hiddenAt = null;
    doc.addEventListener("visibilitychange", function () {
      if (doc.visibilityState === "hidden") { hiddenAt = now(); return; }
      if (hiddenAt && now() - hiddenAt > 60000) reload();
      hiddenAt = null;
    });
  }
  doc.addEventListener("click", function (ev) {
    var b = ev.target.closest ? ev.target.closest("button[data-reload]") : null;
    if (b) { setBusy(b, null, "Reloading…"); reload(); }
  });

  // for passkey.js (busy buttons during a ceremony) and tests (tests/console_ui.mjs): the pure parts and the page's state
  window.OarbankUI = {busyLabel: busyLabel, seconds: seconds, kind: kind, setConn: setConn, conn: conn,
                      busy: function (btn, label) { return setBusy(btn, null, label); }, idle: clearBusy,
                      navigate: function () { startNav(0); }, announce: announce,
                      state: function () { return {navigating: navigating, userRequests: userRequests, busy: busy.length,
                                                   uploading: uploading}; }};

  if (doc.readyState !== "loading") chart(); else doc.addEventListener("DOMContentLoaded", chart);
})();
