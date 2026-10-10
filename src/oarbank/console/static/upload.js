// Upload a folder as a dataset (templates/dataset_upload.html): hash each file with SHA-256 in the browser (incrementally:
// WebCrypto cannot hash a stream), upload it through the console's blob staging routes in resumable chunks (after tus
// 1.0: POST says where the upload stands, PATCH appends at Upload-Offset), then fill datasets.register's parameters.
(function () {
  "use strict";
  var root = document.getElementById("upload");
  if (!root) return;
  var CHUNK = 8 * 1024 * 1024;
  var status = document.getElementById("up-status");
  var csrf = root.dataset.csrf;

  // ---------------------------------------------------------------- SHA-256 (FIPS 180-4), incremental
  var K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);

  function Sha256() {
    this.h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    this.w = new Uint32Array(64);
    this.buf = new Uint8Array(64);
    this.n = 0;          // bytes in buf
    this.len = 0;        // total bytes
  }
  Sha256.prototype.block = function (b, o) {
    var w = this.w, h = this.h, i;
    for (i = 0; i < 16; i++) w[i] = (b[o + 4 * i] << 24) | (b[o + 4 * i + 1] << 16) | (b[o + 4 * i + 2] << 8) | b[o + 4 * i + 3];
    for (i = 16; i < 64; i++) {
      var x = w[i - 15], y = w[i - 2];
      var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    var a = h[0], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7], bb = h[1];
    for (i = 0; i < 64; i++) {
      var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      var t1 = (k + S1 + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
      var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      var t2 = (S0 + ((a & bb) ^ (a & c) ^ (bb & c))) | 0;
      k = g; g = f; f = e; e = (d + t1) | 0; d = c; c = bb; bb = a; a = (t1 + t2) | 0;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
  };
  Sha256.prototype.update = function (data) {
    var i = 0, n = data.length;
    this.len += n;
    if (this.n) {
      while (this.n < 64 && i < n) this.buf[this.n++] = data[i++];
      if (this.n < 64) return;
      this.block(this.buf, 0);
      this.n = 0;
    }
    for (; i + 64 <= n; i += 64) this.block(data, i);
    while (i < n) this.buf[this.n++] = data[i++];
  };
  Sha256.prototype.hex = function () {
    var bits = this.len * 8, pad = new Uint8Array(((this.n < 56 ? 56 : 120) - this.n) + 8);
    pad[0] = 0x80;
    var hi = Math.floor(bits / 0x100000000), lo = bits >>> 0, p = pad.length;
    pad[p - 8] = hi >>> 24; pad[p - 7] = hi >>> 16; pad[p - 6] = hi >>> 8; pad[p - 5] = hi;
    pad[p - 4] = lo >>> 24; pad[p - 3] = lo >>> 16; pad[p - 2] = lo >>> 8; pad[p - 1] = lo;
    this.update(pad);
    var out = "";
    for (var i = 0; i < 8; i++) out += ("00000000" + this.h[i].toString(16)).slice(-8);
    return out;
  };

  function say(text) { status.textContent = text; }
  // overall progress (docs/design/console-loading-states.md): every byte is hashed once and uploaded once, so the work is
  // twice the folder's size; `before` counts the work of the files already done, `current` the file in hand
  var bar = document.getElementById("up-progress"), total = 0, before = 0, current = 0;
  function progress(phase, bytes) {
    if (!bar || !total) return;
    var pct = Math.min(100, Math.floor(100 * (before + (phase === "upload" ? current : 0) + bytes) / (2 * total)));
    bar.hidden = false;
    bar.value = pct;
    bar.setAttribute("aria-valuetext", pct + "% done");
    var b = document.querySelector("#up-start .busy-label");
    if (b) b.textContent = (phase === "upload" ? "Uploading… " : "Hashing… ") + pct + "%";
  }
  function announce(text) { if (window.OarbankUI && window.OarbankUI.announce) window.OarbankUI.announce(text); }

  async function hashFile(file) {
    var h = new Sha256();
    for (var off = 0; off < file.size; off += CHUNK) {
      h.update(new Uint8Array(await file.slice(off, off + CHUNK).arrayBuffer()));
      progress("hash", Math.min(file.size, off + CHUNK));
    }
    return h.hex();
  }

  async function call(method, digest, body, headers) {
    return fetch("/datasets/uploads/" + digest, {method: method, body: body, credentials: "same-origin",
                                                 headers: Object.assign({"x-csrf-token": csrf}, headers || {})});
  }

  async function upload(file, digest, label) {
    for (var tries = 0; tries < 8; tries++) {
      try {
        var r = await call("POST", digest, JSON.stringify({size: file.size}), {"content-type": "application/json"});
        if (!r.ok) throw new Error((await r.json()).detail || r.status);
        var st = await r.json(), offset = st.offset;
        while (!st.complete) {
          var p = await call("PATCH", digest, file.slice(offset, offset + CHUNK), {"upload-offset": String(offset)});
          if (p.status === 409) { offset = Number(p.headers.get("upload-offset")); continue; }
          if (!p.ok) throw new Error((await p.json()).detail || p.status);
          offset = Number(p.headers.get("upload-offset"));
          st.complete = p.headers.get("upload-complete") === "1";
          say(label + ": " + Math.round(100 * offset / Math.max(file.size, 1)) + "%");
          progress("upload", offset);
        }
        return;
      } catch (e) {
        say(label + ": " + e.message + "; retrying");
        await new Promise(function (ok) { setTimeout(ok, 1000 * Math.pow(2, tries)); });
      }
    }
    throw new Error(label + ": upload failed");
  }

  var start = document.getElementById("up-start"), ui = window.OarbankUI;
  start.addEventListener("click", async function () {
    var files = Array.prototype.slice.call(document.getElementById("up-files").files);
    var kind = document.getElementById("up-kind").value.trim();
    if (!files.length || !kind) { say("pick a folder and a kind"); return; }
    var module = document.getElementById("up-module").value, entries = [];
    var top = (files[0].webkitRelativePath || files[0].name).split("/")[0];
    var err = document.getElementById("up-error");
    if (err) err.hidden = true;
    total = files.reduce(function (n, f) { return n + f.size; }, 0); before = 0;
    if (ui) ui.busy(start, "Hashing…");
    announce("Hashing and uploading " + files.length + (files.length === 1 ? " file." : " files."));
    try {
      for (var i = 0; i < files.length; i++) {
        var f = files[i], rel = (f.webkitRelativePath || f.name).split("/").slice(1).join("/") || f.name;
        var label = rel + " (" + (i + 1) + "/" + files.length + ")";
        say(label + ": hashing");
        current = f.size;
        var digest = await hashFile(f);
        await upload(f, digest, label);
        before += 2 * f.size;
        current = 0;
        progress("upload", 0);
        entries.push({path: rel, digest: digest, size: f.size});
      }
    } catch (e) {
      // an interrupted upload resumes where it stopped (the coordinator keeps the offset): Retry continues
      say("");
      if (err) { err.hidden = false; err.querySelector("span").textContent = e.message + ". Nothing was registered; Retry continues where it stopped."; }
      if (ui) ui.idle(start);
      return;
    }
    if (ui) ui.idle(start);
    announce(files.length + (files.length === 1 ? " file" : " files") + " uploaded. Review and register the dataset.");
    var id = document.getElementById("up-id").value.trim() || (kind + ":" + top.replace(/[^A-Za-z0-9_.+-]+/g, "-"));
    var params = {dataset_id: id, kind: kind, files: entries};
    if (module) params.module = module;
    var params_el = document.getElementById("up-params");
    params_el.value = JSON.stringify(params);
    // from a module page's upload link: once registered, go on to the module's importer for this dataset
    if (root.dataset.next) params_el.form.querySelector('input[name="return_to"]').value = root.dataset.next + "&dataset=" + encodeURIComponent(id);
    say(files.length + " files uploaded: review and register the dataset");
    var reg = params_el.form.querySelector("button");
    if (reg) reg.focus();                       // the next step, now that the upload is done
  });
  var retry = document.querySelector("#up-error button");
  if (retry) retry.addEventListener("click", function () { start.click(); });
})();
