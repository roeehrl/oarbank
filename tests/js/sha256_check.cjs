// Checks the console's incremental SHA-256 (src/oarbank/console/static/upload.js) against Node's crypto, fed in uneven
// pieces across block boundaries. Usage: node sha256_check.cjs <upload.js>
const fs = require("fs");
const crypto = require("crypto");
const src = fs.readFileSync(process.argv[2], "utf8");
const m = src.match(/var K = [\s\S]*?Sha256\.prototype\.hex = [\s\S]*?\n  \};/);
if (!m) { console.error("Sha256 not found in upload.js"); process.exit(2); }
eval(m[0]);
let bad = [];
for (const n of [0, 1, 55, 56, 63, 64, 65, 1000, 100000, 3000000]) {
  const data = crypto.randomBytes(n);
  const h = new Sha256();
  let off = 0, step = 1;
  while (off < n) { h.update(new Uint8Array(data.subarray(off, off + step))); off += step; step = step * 3 + 7; }
  if (h.hex() !== crypto.createHash("sha256").update(data).digest("hex")) bad.push(n);
}
if (bad.length) { console.error("mismatch at sizes " + bad.join(", ")); process.exit(1); }
console.log("ok");
