# E2E smoke test — Open Cell Range

Honest summary: **this is a smoke test, not full browser-automation coverage.**
It drives a real Chrome over CDP and checks the handful of things listed
below. Everything else — keyboard navigation, focus behaviour, contrast,
reduced-motion, print output, mobile layout, screen-reader behaviour — is a
**manual checklist** at the bottom of this file. See `docs/ACCESSIBILITY.md`
for the accessibility audit itself; this file is just the test harness.

## What's automated (`smoke.mjs`)

Using `puppeteer-core` to drive a real, already-installed Chrome/Chromium:

1. **The catalogue lists all 9 drills** — reads `data-slug` off every
   `#scenario-groups .scenario` button and asserts the count and that
   `nr-5g-suci-protects` is among them.
2. **Loading a drill, then running it, changes engine-driven state** — loads
   `gsm-2g-imsi-catch`, asserts `#status` is populated, clicks **Run the
   attack**, and asserts `#status` actually changed and `#ue` now reports the
   identity as leaked (this drill is a straightforward IMSI-catch, so this
   also doubles as a sanity check that the check below is testing something
   real, not a UI that always says "protected").
3. **`nr-5g-suci-protects` does not leak** — loads it, runs its attack, and
   asserts `#ue` says "protected" (never "leaked") and `#status` says
   "Permanent identity protected", even after the attack runs.
4. **No console errors** — collects `console.error` messages and uncaught
   `pageerror` exceptions across the whole run and fails if either is
   non-empty.

It does **not** inspect ARIA attributes, contrast, keyboard operability, or
any of the other accessibility-audit items — those are checked by hand (see
`docs/ACCESSIBILITY.md`) and are not practical to assert reliably from a
scripted DOM walk.

## Why `puppeteer-core`, not `puppeteer` or Playwright

The brief's instruction was: try real browser automation, but don't block on
a large download if offline. In this environment `npm` actually had network
access (`npm ping` succeeded), so "install from cache" wasn't the deciding
factor — but the same reasoning still applied: `puppeteer` and Playwright's
default install **download their own bundled Chromium** (100–300MB+).
`puppeteer-core` is the same driver with **no bundled browser** — it only
talks CDP to whatever Chrome/Chromium you already have. On this machine that
install was 84 packages / ~48MB in under 5 seconds, with zero browser
download, using the system's existing `/usr/bin/google-chrome-stable`. If
`npm install` can't reach the registry at all on a given machine (fully
offline, no local cache either), this option genuinely won't work there —
fall back to the manual checklist below in that case.

## How to run it

```sh
cd e2e
npm install          # installs puppeteer-core only, no browser download
npm run smoke         # or: node smoke.mjs
```

The script starts its own tiny static file server for `site/` on a random
free port (no `python3` dependency, and no collision with a `python3 -m
http.server` you might already have running for manual testing), points a
headless Chrome at it, runs the checks above, and exits `0` on success or `1`
if any check failed.

Requirements:
- Node.js (any reasonably recent version; developed against Node 24).
- A Chrome or Chromium binary already installed. The script checks
  `PUPPETEER_EXECUTABLE_PATH`, then `CHROME_PATH`, then common install paths
  (`/usr/bin/google-chrome-stable`, `/usr/bin/chromium`, etc.). If none of
  those match your machine, set one of those two env vars:
  ```sh
  CHROME_PATH=/path/to/chrome node smoke.mjs
  ```
- If no browser is found at all, the script exits with code `2` and a clear
  message — it deliberately does not try to download one.

Other env vars:
- `E2E_SITE_DIR` — serve a different directory than `../site` (e.g. to point
  at a built/deployed copy).
- `E2E_KEEP_OPEN=1` — if any check fails, leave the browser open instead of
  closing it, so you can look at the page state that caused the failure.

## What this caught

Running this script during development caught one real, if minor, bug: the
site had no favicon and no `<link rel="icon">`, so every load triggered an
automatic `GET /favicon.ico` that 404'd and logged a console error — failing
check 4. Fixed in `site/index.html` with a `<link rel="icon" href="data:,">`
(an explicit empty icon, so the browser stops asking). That's the kind of
thing this smoke test is for: it won't catch subtle a11y regressions, but it
does catch "the console isn't actually clean" claims that would otherwise
only be checked by eyeballing DevTools once.

## Manual E2E / accessibility checklist

Things the script above does not (and mostly cannot reasonably) check.
Everything here was walked through by hand during this audit — see
`docs/ACCESSIBILITY.md` for what was found — but there's no substitute for
re-running it after future changes:

**Keyboard**
- [ ] Tab from the top of the page: skip link appears on focus, is the very
  first stop, and activating it (click or Enter) moves focus to "Choose a
  drill" (`#catalogue-heading`) — not just scrolls the page — and the next
  Tab continues from there into the first scenario card.
- [ ] Tab through the whole page once with nothing expanded: order should be
  skip-link → About summary → Workshop summary → course Prev/Open/Next →
  every scenario card in track order → (once a drill is loaded) Run/Reset →
  Tinker summary. No element is skipped, nothing is reachable that shouldn't
  be, nothing traps focus.
- [ ] Open the Workshop `<details>`, Tab through scoreboard reset / the
  instructor-notes checkbox / print-worksheet button, close it, confirm Tab
  no longer stops on those (native `<details>` behaviour — should just work).
- [ ] Load a drill via a scenario card (mouse or keyboard): focus lands on
  the drill's heading (`#stage-title`), not left behind on the card.
- [ ] Every focused element has a visible focus ring in both themes.

**Screen reader spot check** (VoiceOver/NVDA/Orca — whatever's on hand)
- [ ] Page has exactly one H1; heading levels never skip (H1→H2→H3 only).
- [ ] `#status` is announced when it changes (Run/Reset).
- [ ] The findings and flags lists are announced when a drill is run.
- [ ] The active scenario card is announced as pressed/selected.

**Contrast** (both themes — see `docs/ACCESSIBILITY.md` for the numbers)
- [ ] Toggle OS light/dark, re-check severity badges, track badges (2G/4G/
  5G/Defend), and the leaked/protected + cipher state text are all legible.

**Motion**
- [ ] With "reduce motion" on at the OS level, loading a drill jumps
  instantly instead of smooth-scrolling.

**Forms / print**
- [ ] The "Advance the clock by" `<select>` is reachable and operable by
  keyboard, and its label reads correctly with a screen reader.
- [ ] Workshop → "Print the worksheet" opens a print preview showing one
  entry per drill with a working heading structure (not the live app UI).

**Responsive**
- [ ] 375px width: nothing overflows horizontally, buttons stack full-width,
  cards go full-row, arc-strip arrows drop.

**Functional (beyond what smoke.mjs checks)**
- [ ] Guided course Prev/Next clamp at lesson 1 and 9 instead of erroring.
- [ ] Capturing a flag persists across reload (localStorage) and shows up in
  the workshop scoreboard; "Reset this browser's scoreboard" asks for
  confirmation and actually clears it.
- [ ] Instructor-notes toggle shows/hides the notes panel under the loaded
  drill's flags and persists across reload.
- [ ] Tinker "Step the clock" and "Reload & replay the attack" both work
  without needing a drill re-selected from the catalogue first.
