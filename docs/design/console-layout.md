# Console layout rules

The console's pages share one stylesheet, `src/oarbank/console/static/app.css`, under the strict CSP (no inline
script; a style attribute is allowed but a class is preferred). These rules keep every page usable from a 390 px phone
to a 2560 px monitor, in the light and the dark scheme. They came from a visual QA of every page at 390, 1440, 1920 and
2560 px wide: the defects it found (tables wider than their card, actions spilling into the neighbouring card, columns
one word wide, empty grid tracks, the page scrolling sideways on a phone) all came from the few causes the rules below
remove.

## Page and grid

- `main` is at most 1680 px wide, with a fluid side gutter (`clamp(16px, 2.5vw, 40px)`; 10 px on a phone).
- `.grid` is `repeat(auto-fit, minmax(min(100%, 320px), 1fr))`. `auto-fit` collapses empty tracks, so two or three
  cards share the whole row instead of leaving a quarter of it empty; `min(100%, …)` keeps one card from being wider
  than a phone.
- Grid children get `min-width: 0`, so wide content inside a card can never widen the grid track.
- A card that holds a wide table (several columns plus per-row actions) is marked `.wide`: it spans the whole row
  (`grid-column: 1 / -1`). Never `span 2`: with one track (a phone) it would create an implicit second track and
  overflow.
- A grid with wide cards is `.dense`, so small cards fill the holes a wide card leaves. Cards are independent, so the
  visual order may differ from the source order there.
- Cards in a row keep equal heights (the grid's default stretch).

## Overflow: contain it, never let it spill

- A card (`.card`, and a module's `.mod-section`) is a horizontal scroll container (`overflow-x: auto`) and is
  `position: relative`, so an absolutely placed `.sr-only` label inside it cannot widen the page. Scrolling inside a
  card is the last resort; the rules below make it rare on a desktop.
- Below 760 px a table is `display: block; overflow-x: auto`: it scrolls inside itself and the page never scrolls
  sideways. Prose cells keep `min-width: 7rem` and monospace cells `12rem`, so a narrow screen scrolls the table rather
  than wrapping a column one word per line.
- Wrapping: table headers never wrap (`th { white-space: nowrap }`); text cells wrap between words
  (`overflow-wrap: break-word`, which does not shrink a column's minimum width); ids, hashes, paths and JSON (`td.mono`,
  `.mono` inside a cell or a `.kv`) may break anywhere. Short labels that must stay on one line (a release id, a
  platform, a size, chips inside a table, a number field with its unit) are `.nowrap`.
- A long value that is cut (a digest, a key) is cut in the template (`[:12]`, `[:16]`) and carries the full value in
  `title`.

## Actions

- Per-row actions live in a `td.actions` cell (never `td.row`, which turns the cell into a flex box and breaks the
  table): a right-aligned group of inline forms and `details` that wraps between buttons, never inside one. An opened
  `details` (for example a signature form) becomes a block of at most 32 rem below the buttons.
- Inside an inline form a field and its button are 4 px apart (`form.inline > input/select/label`).
- Card-level actions sit in a `.row` with a `.sp` spacer, right-aligned (for example Releases → Build release).
- Buttons are at least 28 px high; `a.btn` looks like a button (no underline).

## Forms

- `.stack` (on the Settings grid) stacks forms: each label above its full-width field, the action button on its own
  line. Inline rows of label + field stay for short filter forms (`form.row`).
- Field borders use `--field` (3:1 against the card in both schemes, WCAG 1.4.11); every control has a visible
  `:focus-visible` outline in the accent colour.

## Spacing and type

- Spacing comes from `--s1`..`--s5` (4, 8, 12, 16, 24 px). Consecutive top-level cards and a table followed by a card
  are 12 px apart.
- Table cells align on the text baseline, so a row with buttons lines up with its text.
- A module's section navigation marks the current page (`aria-current`) with weight and an accent underline.
- Empty tables show a one-line empty state (`{% else %}<tr><td colspan=…>`), never a lone header row.

## Checking a change

Run a throwaway coordinator and console against a copy of a home (never the live one) and look at every page at 390,
1440, 1920 and 2560 px, in both schemes, with `details` closed and open. A quick probe in the browser console finds
the usual regressions:

```js
// elements past the viewport that no scroll container clips
const W = document.documentElement.clientWidth;
[...document.querySelectorAll('main *')].filter(el => {
  if (el.getBoundingClientRect().right <= W + 1) return false;
  for (let a = el.parentElement; a; a = a.parentElement) if (getComputedStyle(a).overflowX !== 'visible') return false;
  return true;
});
```
