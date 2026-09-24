# Accessibility audit

An audit-with-fixes pass over `site/`, checked against WCAG 2.1 AA. Scope was
`site/` only — `site/js/engine-wasm.js`, `engine-mock.js`'s data shape, and
`site/pkg` were not touched; every fix here is markup, CSS, or UI-only JS in
`site/index.html`, `site/css/style.css`, and `site/js/app.js`.

Verified live against `python3 -m http.server -d site 8166`, driven with the
browser tools: tabbed through every control, ran drills (including
`nr-5g-suci-protects`), toggled light/dark via `prefers-color-scheme`
emulation, tested a 375px mobile width, and confirmed the console stayed
clean throughout. Contrast ratios below were computed exactly (WCAG relative-
luminance formula), not eyeballed — see the numbers inline.

## Fixed

### 1. Heading hierarchy skipped a level (H1 → H3)

The Workshop panel's "Scoreboard", "Instructor notes", and "Worksheet"
headings were `<h3>`, appearing directly after the page's only `<h1>` with no
intervening `<h2>` — a level-skip that breaks heading-based navigation for
screen-reader users. **Fixed**: promoted all three to `<h2>` in
`site/index.html`; `site/css/style.css`'s `.workshop-body h3` rule became
`.workshop-body h2` (same `font-size`/`margin`, now explicit `font-weight:
600` so it doesn't rely on the browser's default h2/h3 bold), so nothing
visually changed. Verified live: the page now has exactly one `<h1>` and no
skipped levels anywhere, including inside the hidden `#stage` and `#worksheet`
subtrees (checked programmatically by walking every `h1`–`h4` in the DOM).

### 2. A second `<h1>` in the print-only worksheet

`#worksheet` (populated by `app.js`, shown only via `@media print`) had its
own `<h1>Open Cell Range — workshop worksheet</h1>`, and each entry inside it
was an `<h2>`. Two `<h1>`s on one page is itself a violation regardless of
the print-only visibility, and it also meant the per-drill entries (`<h2>`)
were one level below a `<h1>` that visually-hidden screen readers might still
enumerate. **Fixed**: worksheet title is now `<h2>`, per-entry headings are
now `<h3>` (`site/index.html`, `site/js/app.js`'s `renderWorksheet()`, and
the corresponding `@media print` selectors in `style.css`). Print layout is
visually unchanged — the print CSS sets explicit `font-size`/`margin` on
these selectors regardless of tag name.

### 3. Skip link didn't actually move focus

`<a class="skip-link" href="#catalogue-heading">` scrolled the page to
"Choose a drill" but the target `<h2>` wasn't focusable, so keyboard focus
stayed wherever it was (or silently fell back to `<body>` in most browsers) —
the *visual* jump worked but the *keyboard* skip did not, defeating the
point of a skip link for the keyboard users it exists for. **Fixed**: added
`tabindex="-1"` to `#catalogue-heading` (`site/index.html`). Verified live:
clicking the skip link now moves `document.activeElement` to the heading,
and the next Tab press continues into the first scenario card, exactly as
intended.

### 4. No focus management when a drill loads

Clicking a scenario card (or "Open this lesson in the sandbox") revealed and
populated `#stage` below/beside the trigger, but focus stayed on the button
just clicked — a keyboard or screen-reader user got no cue that new content
had appeared, and had to manually navigate to find it. **Fixed**
(`site/js/app.js`'s `load()`): added `tabindex="-1"` to `#stage-title`
(`site/index.html`) and call `.focus({ preventScroll: true })` on it right
after rendering the loaded drill, so focus (and the screen-reader
announcement that comes with it) lands on the new content directly.
`preventScroll` avoids a second, competing scroll on top of the existing
`scrollIntoView` call. Verified live for both a mouse click on a catalogue
card and the course's "Open this lesson" button.

### 5. `prefers-reduced-motion` was not honoured

The only animated behaviour in the UI — `$('stage').scrollIntoView({
behavior: 'smooth', ... })` on drill load — ignored the user's reduced-motion
preference. **Fixed**: `app.js` now checks
`window.matchMedia('(prefers-reduced-motion: reduce)').matches` (read live,
not cached, so an OS-level change mid-session is respected) and uses
`behavior: 'auto'` when set; `style.css` also gained a defensive
`@media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }`
as a belt-and-suspenders fallback. No CSS `transition`/`animation` rules
exist anywhere else in the stylesheet, so this was the only motion to
address. Verified live by forcing `matchMedia` to report reduced-motion and
spying on the resulting `scrollIntoView` call — confirmed it received
`behavior: "auto"` (and `"smooth"` with the preference off).

### 6. Contrast failure: the 2G track badge

The "2G" badge (`.track-2g .track-badge`) used a hardcoded `#ff9db1` for
text and border in **both** themes. That pink reads fine on the dark theme's
near-black background (9.58:1 / 8.73:1 against `--bg`/`--panel` — comfortably
passes) but **fails badly in light mode**: 1.81:1 against `--bg` and 1.96:1
against `--panel`, far under the WCAG AA minimum (4.5:1 for text, or 3:1 even
under the more lenient non-text/large-text threshold). Every other
track/severity/state colour in the stylesheet was computed the same way and
all of them pass (5.2:1–15.9:1 range) — this was the one outlier.
**Fixed**: introduced a theme-aware `--track-2g` custom property —
`#c2255c` in light (5.22:1 on `--bg`, 5.66:1 on `--panel`) and the original
`#ff9db1` kept for dark (already passing) — and pointed
`.track-2g .track-badge` at `var(--track-2g)` instead of the hardcoded hex.
Verified both by computing exact contrast ratios for every colour token in
both themes (script-checked, not eyeballed) and visually in the browser at
both light and dark.

### 7. Missing favicon logged a console error on every load

Not originally an "accessibility" item, but surfaced by the new E2E smoke
test's "no console errors" check: with no favicon file and no `<link
rel="icon">`, every page load triggered an automatic `GET /favicon.ico` that
404'd and logged a console error. **Fixed**: added
`<link rel="icon" href="data:," />` — an explicit empty icon that stops the
browser from requesting one. Verified: `read_network_requests` shows no more
favicon request, and the console stays empty across a full interaction pass
(catalogue → load → run → reset → course nav → tinker → instructor notes).

## Audited and already correct (no change needed)

These were checked against the brief's checklist and found already
compliant — noted here so the audit is a complete record, not just a diff:

- **`aria-live` regions**: `#status` (`role="status" aria-live="polite"`),
  `#findings`, `#flags`, and the course progress block already had them,
  covering exactly the regions the brief called out (status/findings/flags).
  Not extended to `#cells`/`#ue` — `#status` already summarises their state
  in one sentence, and live-announcing the whole cell/phone panel on every
  run would be noisy without adding information `#status` doesn't already
  carry.
- **`aria-pressed` on persistent selection**: every scenario card sets
  `aria-pressed="true"/"false"` in sync with its `.active` CSS class
  (`markActiveScenario()` in `app.js`), so sighted and screen-reader users
  get the same "which drill is loaded" signal.
- **Buttons vs. links**: every state-changing control is a real `<button
  type="button">`; every navigational element (About/Ethics links, footer,
  GitHub source) is a real `<a href>`. No click-handler-on-`<div>` or
  link-as-button anti-patterns found.
- **No keyboard traps**: `<details>`/`<summary>` (About, Workshop, Tinker)
  are native disclosure widgets — children of a closed `<details>` are
  natively excluded from the tab order by the browser, no custom JS
  involved, so there's nothing to trap focus. No modals exist anywhere in
  the UI.
- **Forms are labelled**: the step-size `<select id="step-amount">` has a
  proper `<label for="step-amount">`; the instructor-notes `<input
  type="checkbox">` is wrapped in its `<label>` text. `role="group"
  aria-label="…drills"` on each track's button row identifies the grouping
  for assistive tech.
- **Contrast, every other token**: all severity colours (High/Medium/
  Low/Info, both as badge-on-tint and plain text), the leaked/protected and
  cipher state text, the 4G/5G/Defend track badges, and every `.muted`
  greyscale-text usage were computed against every background they actually
  appear on, in both themes — all pass at 4.5:1 or better except the one
  fixed above (details: severities range 4.99:1–7.92:1; body/muted text
  4.66:1–15.9:1).
- **Zoom**: the viewport meta tag has no `maximum-scale`/`user-scalable=no`,
  so pinch-zoom and browser text-zoom both work.
- **Severity/state never colour-only**: already icon + colour + word
  everywhere (⛔/▲/◆/ℹ for severity, ⚠/✓ for leaked/protected and
  captured/not) — confirmed still true after the fixes above; nothing here
  needed to change.

## Deferred (with reasons)

- **`docs/UI.md` says "seven drills/scenarios"**, stale since the catalogue
  grew to nine. Out of scope for this pass — the brief's scope excludes
  "other docs" (only `docs/ACCESSIBILITY.md` was in scope to create/edit).
  Flagging here for whoever next touches `docs/UI.md`.
- **`#ue`'s three facts (camped on / identity / cipher) are plain `<div>`s**,
  not a `<dl>`. They're already screen-reader-readable (bold labels, no
  colour-only meaning) and not a WCAG failure — converting to `<dl>` would
  be a markup-and-CSS change with layout risk for a readability upgrade, not
  a fix, so it was left alone to keep this pass low-risk and scoped to
  actual failures.
- **Scenario card accessible names are verbose** (badge + title + brief
  concatenated, e.g. "2G Catch an IMSI on 2G Stand up a rogue cell…").
  Still meaningful and non-empty, just long. Fixing this well would mean
  either shortening the visible brief (a content/design decision outside
  this audit's remit) or adding an `aria-label` that duplicates/diverges
  from visible text (its own anti-pattern) — deferred rather than picking
  one without a clear win.
- **`document.title` doesn't update per loaded drill.** Single-page app with
  no route changes; not a WCAG requirement. Would be a minor orientation
  aid for browser-tab users running multiple drills across tabs, but adds
  another piece of state to keep in sync for a marginal benefit — deferred.
- **`window.confirm()` for "Reset this browser's scoreboard"** — pre-existing,
  unmodified code. Native `confirm()` dialogs are accessible by default;
  verified by code review only (a synthetic dialog in headless/automated
  testing risks hanging the test), not re-tested live in this pass.

## Verification summary

- **Console**: clean (`read_console_messages`) through a full interaction
  pass — load site, run every check in `e2e/smoke.mjs`, toggle instructor
  notes, step/replay via Tinker, walk course Prev/Next to both ends.
- **Light / dark**: checked via `prefers-color-scheme` emulation; contrast
  numbers above hold in both.
- **Mobile (375px)**: catalogue, stage panels, findings/flags, and the
  Tinker controls all reflow correctly; buttons go full-width; no horizontal
  overflow.
- **Keyboard**: skip link → focus lands on `#catalogue-heading` → Tab
  continues into the first scenario card; loading a drill moves focus to
  `#stage-title`; `<details>` panels have no reachable-while-closed content.
- **Automated**: `e2e/smoke.mjs` (see `e2e/README.md`) exercises the
  functional side of several of these paths (catalogue count, state changes
  on load/run, `nr-5g-suci-protects` non-leak, console cleanliness) on every
  run — it's not an accessibility checker, but it does guard against a
  regression silently breaking the console-clean claim above.
