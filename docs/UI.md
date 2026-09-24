# UI notes (seed — expanded by the site work)

Design posture inherited from the owner's stated preferences: surface tensions, warn rather
than block, name things by what they do, and design so a learner cannot misread the state.

- The sandbox is always live; drills drive the same world rather than a separate mock.
- The snapshot the UI renders never contains ground truth a learner is meant to infer
  (which cell is rogue) — see `site/ENGINE-API.md`.
- Threat/severity colour must stay distinguishable for colour-vision-deficient users; do
  not rely on red/green alone. Pair colour with the severity word and an icon.
- Every control that has an effect is shown; nothing that still does something is hidden.
