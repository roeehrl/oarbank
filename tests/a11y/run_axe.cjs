// Run axe-core (WCAG 2.0/2.1 A and AA rules) over saved HTML pages in jsdom.
//   NODE_PATH=<dir with axe-core and jsdom> node run_axe.cjs page1.html page2.html ...  -> JSON on stdout
// jsdom has no layout, so rules that need rendering (colour contrast) come back "incomplete"; the Python
// side checks the stylesheet's colour tokens for contrast instead.
const fs = require("fs");
const { JSDOM } = require("jsdom");
const axeSource = fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");

async function check(file) {
  const dom = new JSDOM(fs.readFileSync(file, "utf8"), { runScripts: "outside-only", pretendToBeVisual: true });
  dom.window.eval(axeSource);
  const r = await dom.window.axe.run(dom.window.document, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules: { "color-contrast": { enabled: false }, "region": { enabled: false } },
  });
  return { file, violations: r.violations.map(v => ({ id: v.id, impact: v.impact, help: v.help,
    nodes: v.nodes.slice(0, 5).map(n => n.target.join(" ")) })) };
}

(async () => {
  const out = [];
  for (const f of process.argv.slice(2)) out.push(await check(f));
  process.stdout.write(JSON.stringify(out));
})();
