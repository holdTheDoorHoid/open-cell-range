# UI notes

Design posture inherited from the owner's stated preferences: surface tensions, warn rather
than block, name things by what they do, and design so a learner cannot misread the state.
This document records the decisions made while building `site/` and the reasoning behind
each — not a restatement of the code, but why it looks the way it does.

## The seam

`site/js/app.js` is the only file that imports the engine
(`import { createEngine } from './engine-mock.js'`). Every render function works from the
`Snapshot` object alone; nothing in the UI reaches past it into engine internals. That is
what lets `engine-mock.js` be swapped for `engine-wasm.js` later by changing one line and
nothing else. Concretely: `render(snap)` in `app.js` never inspects `snap.scenario` to
special-case a drill's visuals — the 2G-vs-5G contrast the drills are built around comes
entirely from the generic `ue.imsi_leaked` / findings-severity rendering reacting differently
to different data, not from per-scenario UI branching. If a future drill needs
scenario-specific chrome, that is a signal the snapshot shape is missing a field, and the fix
belongs in `ENGINE-API.md` first.

## Reading `imsi_leaked` across generations

The frozen snapshot contract has exactly one boolean for "the permanent identifier crossed
the air in the clear": `ue.imsi_leaked`. Two of the seven drills — `nr-5g-suci-protects` and
`nr-5g-null-scheme` — are about the 5G identifier (SUPI), not the IMSI by name. Rather than
inventing a second field (which `ENGINE-API.md` forbids without amending the contract first,
and which the real wasm engine would then also need to grow), this project reads the
existing field at the level it actually operates: "was the permanent subscriber identity
recoverable in the clear," independent of what the generation calls that identifier. The
UI's copy does the disambiguation instead of the schema — cell/event/finding text says IMSI
or SUPI explicitly depending on the drill, while the boolean and its rendering path
(`stateBadge` in `app.js`) stay generic. This keeps one code path serving all seven drills and
keeps the contract exactly as specified.

## Grouping by track is the point, not a nicety

`ENGINE-API.md` already carries `track: "2g"|"4g"|"5g"|"defend"` on every `Scenario`. The
catalogue (`renderScenarios` in `app.js`) groups by that field into four `<section>`s in a
fixed order (2G → 4G → 5G → Defend), each headed by a description of *what changed and what
didn't* for that generation, rather than a flat button list. DESIGN.md section 2 states the
whole arc's value is being one story across generations; a flat list of seven buttons in
catalogue order would carry that story only in the reader's memory of ordering. Grouped
headings carry it in the page itself. The decorative arc strip in the header (`.arc`,
`aria-hidden="true"` since the grouped headings already carry the same information
accessibly) exists for the same reason at a glance, before a learner has picked anything.

## The 5G-protects contrast is structural, not styled

The instruction to make `nr-5g-suci-protects` "visibly contrast" with the 2G leak was
deliberately **not** solved by adding a special "success" banner or scenario-specific
component. It's solved by making sure the generic rendering already produces a visible
contrast when the underlying data differs:

- `ue.imsi_leaked = false` renders as `✓ protected` in the good colour, where the 2G/4G/
  null-scheme drills render `⚠ leaked` in the bad colour, from the exact same `stateBadge()`
  call.
- The findings panel's worst severity differs sharply: 2G/4G drills raise a `High`
  `CleartextIdentityRequest`; the SUCI-protects drill raises only `Info`/`Low` findings. The
  severity badge's colour, icon, and word all change together, so the contrast reads even at
  a glance or in greyscale.
- The event log's final message explicitly says so in-world ("Compare this to the 2G and 4G
  drills: the request looks the same, the answer does not") rather than leaving the learner to
  infer it from a UI change alone.

This means the contrast will still be visible and correct once `engine-mock.js` is replaced
by the real wasm engine, because nothing about it lives in scenario-specific UI code.

## Severity and state are never colour-only

Every place the UI communicates threat level or a leaked/protected state pairs three signals:
a colour, a distinct icon/shape, and the word itself in text — so the meaning survives colour-
vision deficiency and greyscale printing. Concretely:

| Severity | Icon | Colour token |
|---|---|---|
| High | ⛔ (octagon) | `--bad` (red) |
| Medium | ▲ (triangle) | `--warn` (amber) |
| Low | ◆ (diamond) | `--low` (teal) |
| Info | ℹ (circle) | `--info` (indigo/blue) |

Four distinct shapes were chosen deliberately (not just red/amber/grey/grey) so that even a
fully colour-blind reading of the icon alone disambiguates all four levels. The same pattern
applies to `ue.imsi_leaked` / `ue.null_cipher_active` (⚠ + word + red vs ✓ + word + green) and
to flags (✓ Captured vs ○ Not yet, plus the word, plus colour). No `sev-*` or state CSS class
is ever the only thing distinguishing two states — check `site/css/style.css`'s `.sev-*`
rules, which set a border colour *and* a badge background *and* rely on the badge text
carrying the word.

## Every control that has an effect is visible

There are exactly two controls that change engine state: **Run the attack / Run the
monitor** and **Reset this drill**. Both are always shown together once a drill is loaded;
neither is ever hidden or disabled based on state (running an already-run attack simply
re-renders the same post-attack snapshot; the mock engine is idempotent per phase, so there
is nothing unsafe about leaving Run clickable). This follows the instruction directly: no
control that still does something is ever hidden.

The run button's label changes per track (`RUN_LABEL` in `app.js`): "Run the attack" for the
2G/4G/5G tracks, **"Run the monitor" for the defend track**, because clicking it there does
not create an attack — the attack already happened before the drill loaded, per
`docs/CURRICULUM.md`'s "Spot the catcher" entry. Naming the control by what it actually does
(rather than keeping one static label everywhere) was judged more important than label
consistency across tracks.

## Warnings over blocking

Nothing in the UI is ever disabled-and-unexplained. A flag not yet captured shows its hint
inline (why it isn't captured and what would capture it) rather than graying out a control.
The About panel is a `<details>` a learner can skip, not a modal blocking the first
interaction — consistent with "warn rather than block."

## Design so a learner cannot misread the state

- A `role="status" aria-live="polite"` line (`#status`) always states, in one sentence, the
  exact machine-checkable state: message count, whether the permanent identity is leaked or
  protected, finding count, and `n/total` flags captured. This exists specifically so the
  state is never something a learner has to reconstruct by cross-referencing three panels —
  and so screen-reader users get the same summary sighted users get from scanning the page.
- The currently-selected scenario card gets a visible active state (thicker accent border)
  **and** `aria-pressed="true"`, so keyboard/screen-reader users and sighted users get the
  same signal about which drill is loaded.
- The cell the phone is camped on is visually distinguished in the cell list (tinted row +
  an explicit "📶 phone camped here" badge) rather than left for the learner to cross-reference
  `ue.camped_on` against the cell id list by hand.
- Ground truth the learner is meant to infer is never in the snapshot or the UI: cells carry
  only what a real observer could see (id, RAT, PLMN, signal, area code) — never a
  `legitimate` flag. The monitor's findings draw conclusions from that same observable
  evidence (e.g. "area code 65535 — the reserved maximum, never assigned on a live network"),
  exactly as a real detector would, which is different from the UI asserting hidden ground
  truth directly.

## Light and dark theme

The previous stylesheet was dark-only. `site/css/style.css` now defines the light palette as
the unconditional `:root` default and overrides it inside
`@media (prefers-color-scheme: dark)`, matching the system setting automatically — there is
no manual toggle, since the instruction was to support both via `prefers-color-scheme`
specifically, and adding a stateful toggle would be a second thing to keep in sync with no
clear win over following the OS setting. Contrast was checked by eye in both modes for the
four severity colours against both `--panel` and `--bg`; verified live in the browser pane
(see below).

## Responsive layout

The three-panel grid (`the air` / `messages` / `what a monitor sees`) collapses to a single
column at 860px, matching the existing breakpoint philosophy but widened slightly from the
original 800px after checking common tablet widths. A second breakpoint at 560px stacks the
run/reset buttons full-width, drops the arc strip's arrows (redundant once the steps wrap to
their own lines), and lets scenario cards take the full row width instead of a fixed 260px,
which otherwise left an awkward sliver of empty space next to a single card per row on phone
widths.

## Verification

Checked live against `python3 -m http.server -d site 8137` in the browser pane:
catalogue renders grouped by track; loading a drill shows its brief and an idle world;
running the attack updates cells/events/findings/flags together and the status line; the
`nr-5g-suci-protects` drill's post-attack state shows `imsi_leaked: false` throughout (no
IMSI/SUPI leak) with only Info/Low findings, contrasting with `gsm-2g-imsi-catch`'s leaked
state and High finding; the About panel expands via a real click; light and dark
(`prefers-color-scheme`) and a 375px mobile width all render correctly; `console` stayed
empty throughout. All seven scenarios were additionally validated programmatically against
the field types, enum spellings, and event-ordering rules in `ENGINE-API.md`.
