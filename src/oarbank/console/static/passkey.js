// Passkey ceremonies for the console (WebAuthn). The server holds the challenges; this file only converts between
// base64url JSON and the ArrayBuffers navigator.credentials wants. No inline script (strict CSP).
(function () {
  "use strict";
  function b64uToBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function bufToB64u(b) {
    var bytes = new Uint8Array(b), bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function csrf() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.content : "";
  }
  function post(url, body) {
    return fetch(url, {method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf()}, body: JSON.stringify(body || {})})
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.detail || j.error || r.status); return j; }); });
  }
  function status(msg) {
    var el = document.querySelector("[data-passkey-status]");
    if (el) el.textContent = msg;
  }
  function cred(c) {
    var r = c.response, out = {id: c.id, rawId: bufToB64u(c.rawId), type: c.type, response: {
      clientDataJSON: bufToB64u(r.clientDataJSON)}, clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {}};
    if (r.attestationObject) out.response.attestationObject = bufToB64u(r.attestationObject);
    if (r.getTransports) out.response.transports = r.getTransports();
    if (r.authenticatorData) out.response.authenticatorData = bufToB64u(r.authenticatorData);
    if (r.signature) out.response.signature = bufToB64u(r.signature);
    if (r.userHandle) out.response.userHandle = bufToB64u(r.userHandle);
    if (c.authenticatorAttachment) out.authenticatorAttachment = c.authenticatorAttachment;
    return out;
  }
  document.addEventListener("click", function (ev) {
    var t = ev.target;
    if (!(t instanceof HTMLElement)) return;
    if (!window.PublicKeyCredential && (t.dataset.passkeyLogin !== undefined || t.dataset.passkeyRegister !== undefined)) {
      status("This browser has no passkey support here (passkeys need https or http://localhost)."); return;
    }
    if (t.dataset.passkeyLogin !== undefined) {
      status("Waiting for your passkey…");
      post("/login/passkey/options").then(function (o) {
        var pk = o.options;
        pk.challenge = b64uToBuf(pk.challenge);
        (pk.allowCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });
        return navigator.credentials.get({publicKey: pk}).then(function (c) {
          return post("/login/passkey", {challenge_id: o.challenge_id, credential: cred(c), next: t.dataset.next || "/"});
        });
      }).then(function (r) { window.location = r.next || "/"; }).catch(function (e) { status("Not signed in: " + e.message); });
    }
    if (t.dataset.passkeyRegister !== undefined) {
      var label = (document.querySelector("[data-passkey-label]") || {}).value || "passkey";
      status("Follow your browser's prompt…");
      post("/account/passkey/options").then(function (o) {
        var pk = o.options;
        pk.challenge = b64uToBuf(pk.challenge);
        pk.user.id = b64uToBuf(pk.user.id);
        (pk.excludeCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });
        return navigator.credentials.create({publicKey: pk}).then(function (c) {
          return post("/account/passkey", {challenge_id: o.challenge_id, credential: cred(c), label: label});
        });
      }).then(function () { status("Passkey added."); window.location.reload(); })
        .catch(function (e) { status("Not added: " + e.message); });
    }
  });
})();
