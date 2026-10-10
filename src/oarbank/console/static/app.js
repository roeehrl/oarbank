// oarbank-console behaviour. Everything binds through data- attributes: no inline script (strict CSP).
(function () {
  "use strict";

  // CSRF: every POST form and every htmx request carries the session's token (meta csrf-token).
  function csrfToken() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.content : "";
  }
  document.addEventListener("htmx:configRequest", function (ev) {
    ev.detail.headers["X-CSRF-Token"] = csrfToken();
  });

  // T1 operations confirm in the browser; some ask for a reason (sent with the operation).
  document.addEventListener("submit", function (ev) {
    var f = ev.target;
    if (!(f instanceof HTMLFormElement)) return;
    if ((f.method || "").toLowerCase() === "post" && !f.querySelector('input[name="csrf"]')) {
      var c = document.createElement("input");
      c.type = "hidden"; c.name = "csrf"; c.value = csrfToken();
      f.appendChild(c);
    }
    if (f.dataset.confirm && !window.confirm(f.dataset.confirm)) { ev.preventDefault(); return; }
    if (f.dataset.reason === "prompt") {
      var r = window.prompt("Reason (recorded in the audit log):", "");
      if (r === null) { ev.preventDefault(); return; }
      var inp = f.querySelector('input[name="reason"]');
      if (inp) inp.value = r;
    }
    var b = f.querySelector("button");
    if (b) setTimeout(function () { b.disabled = true; }, 0);   // no double submit (the idempotency key is the guarantee)
  }, true);

  // Caps table: a row's number input is enabled only while its checkbox is on.
  document.addEventListener("change", function (ev) {
    var t = ev.target;
    if (t.matches && t.matches("input[data-toggles-row]")) {
      var n = t.closest("tr").querySelector("input[type=number]");
      if (n) n.disabled = !t.checked;
    }
  });

  // Protection editor: the process picker appends a suggested rule to the JSON editor, then re-runs the preview.
  document.addEventListener("click", function (ev) {
    var b = ev.target.closest ? ev.target.closest("button[data-add-rule]") : null;
    if (!b) return;
    var ta = document.getElementById(b.dataset.target);
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
    var range = document.createRange();
    range.selectNodeContents(el);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
  function copied(b, ok) {
    var was = b.dataset.label || b.textContent;
    b.dataset.label = was;
    b.textContent = ok ? "Copied" : "Press Cmd/Ctrl+C";
    setTimeout(function () { b.textContent = was; }, 1800);
  }
  document.addEventListener("click", function (ev) {
    var b = ev.target.closest ? ev.target.closest("button[data-copy]") : null;
    if (!b) return;
    var el = document.getElementById(b.dataset.copy);
    if (!el) return;
    function legacy() {
      selectText(el);
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
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
    var el = document.getElementById("chart");
    if (!el || !window.uPlot || el.dataset.drawn) return;
    var S = JSON.parse(el.dataset.series || "{}");
    el.dataset.drawn = "1";
    if (!S.t || S.t.length < 2) { el.textContent = "no samples yet"; return; }
    new uPlot({width: Math.min(document.querySelector("main").clientWidth - 40, 1300), height: 220,
      series: [{}, {label: "mem GB", stroke: "#12a150"}, {label: "running", stroke: "#d68a00"},
               {label: "slots", stroke: "#98a2b3", dash: [4, 4]}, {label: "reserved GB", stroke: "#d92d20"}],
      axes: [{}, {}]}, [S.t, S.mem, S.busy, S.slots, S.reserved], el);
  }

  // Staleness watchdog: three missed heartbeats (~15 s) grey out live tiles and disable every control
  // except the fleet pause; a new server_boot_id reloads the page (templates and assets changed).
  var lastBeat = Date.now(), builtAt = null, boot = document.body.dataset.boot;
  document.body.addEventListener("htmx:sseMessage", function (ev) {
    if (ev.detail.type !== "heartbeat") return;
    try {
      var hb = JSON.parse(ev.detail.data);
      lastBeat = Date.now();
      builtAt = hb.built_at;
      if (boot && hb.server_boot_id && hb.server_boot_id !== boot) { window.location.reload(); return; }
      document.body.classList.toggle("stale", hb.coordinator_ok === false);
    } catch (e) { /* ignore */ }
  });
  document.body.addEventListener("htmx:sseError", function () { document.body.classList.add("stale"); });
  setInterval(function () {
    var age = (Date.now() - lastBeat) / 1000;
    if (age > 15) document.body.classList.add("stale");
    var s = document.getElementById("stale-age");
    if (s && builtAt) s.textContent = new Date(builtAt * 1000).toLocaleTimeString() + " (" + Math.round(Date.now() / 1000 - builtAt) + " s ago)";
  }, 2000);
  // A tab that was hidden for over a minute resyncs when it comes back (htmx 2 has no pauseOnBackground).
  var hiddenAt = null;
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "hidden") { hiddenAt = Date.now(); return; }
    if (hiddenAt && Date.now() - hiddenAt > 60000) window.location.reload();
    hiddenAt = null;
  });

  if (document.readyState !== "loading") chart(); else document.addEventListener("DOMContentLoaded", chart);
})();
