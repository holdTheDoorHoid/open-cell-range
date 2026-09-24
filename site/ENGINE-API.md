# The engine contract

What `site/` needs from `crates/ocr-wasm`. The front end talks to exactly one object.

Two implementations of this contract ship:

- **`site/js/engine-wasm.js`** — the real engine, `crates/ocr-wasm` compiled to
  WebAssembly. This is what `site/js/app.js` imports for production.
- **`site/js/engine-mock.js`** — a JavaScript reference implementation of this same
  contract, with canned-but-honest data. Kept deliberately: it is the readable statement of
  what this document means, and it lets the site be developed and deployed without a Rust
  toolchain or a `site/pkg` build.

Switching between them is one line in `site/js/app.js`:

```js
import { createEngine } from './engine-mock.js';   // ← reference, no build needed
import { createEngine } from './engine-wasm.js';   // ← the real engine
```

Nothing else in the site imports the engine. If you need to change a second file, this
contract is wrong and should be fixed here first.

Build the real one with:

```
wasm-pack build crates/ocr-wasm --target web --out-dir ../../site/pkg
```

`site/pkg` is generated and git-ignored; CI builds it before deploying.

---

## The object

`createEngine()` returns an object (wrapping the wasm `Engine`) with these methods. Every
method that changes state returns a **state snapshot** (below). All values cross the
boundary as JSON, parsed on the JS side.

| method | returns | meaning |
|--------|---------|---------|
| `listScenarios()` | `Scenario[]` | the drill catalogue, in teaching order |
| `load(slug)` | `Snapshot` | build a scenario and reset the world |
| `runAttack(attackerId)` | `Snapshot` | run one attacker actor against the world |
| `step(dtUs)` | `Snapshot` | advance the virtual clock by microseconds |
| `reset()` | `Snapshot` | rebuild the loaded scenario |
| `state()` | `Snapshot` | the current snapshot without changing anything |

### `Scenario`

```json
{ "slug": "gsm-2g-imsi-catch",
  "title": "Catch an IMSI on 2G",
  "brief": "Stand up a rogue cell and ask the phone who it is.",
  "track": "2g" }
```

`track` is one of `"2g" | "4g" | "5g" | "defend"`, so the UI can group the arc.

### `Snapshot`

The one shape the whole UI renders from. Ground truth the learner must infer (which cell is
rogue) is **not** in the snapshot beyond what a real observer could see; `legitimate` is
never sent.

```json
{
  "version": 3,
  "scenario": "gsm-2g-imsi-catch",
  "now_us": 400000,
  "cells": [
    { "id": 1, "rat": "gsm", "plmn": "310-260", "signal_dbm": -70, "area_code": 4102 },
    { "id": 7, "rat": "gsm", "plmn": "310-260", "signal_dbm": -45, "area_code": 9999 }
  ],
  "ue": { "camped_on": 7, "camped_rat": "gsm",
          "imsi_leaked": true, "null_cipher_active": false },
  "events": [
    { "t_us": 380000, "rat": "gsm", "cell": 7, "dir": "net_to_ue",
      "msg": "IdentityRequest(IMSI)", "summary": "Rogue cell asks the phone for its IMSI" }
  ],
  "findings": [
    { "kind": "CleartextIdentityRequest", "severity": "High", "t_us": 380000,
      "detail": "A cell requested the permanent identity in the clear." }
  ],
  "flags": [
    { "id": "imsi-in-hand", "title": "Recover the IMSI", "captured": true,
      "hint": "The phone will answer an Identity Request before it trusts the cell." }
  ]
}
```

Field notes:

- `version` bumps on every state-changing call so the UI can detect staleness.
- `plmn` is rendered `"MCC-MNC"`.
- `events` is the recent air log, newest last, already summarised for display.
- `findings` come straight from `ocr-detect`; severity is `"Info"|"Low"|"Medium"|"High"`.
- `flags[].captured` is evaluated on engine state, never on user input — capturing a flag
  means the world actually reached the state, per DESIGN.md.

## Versioning this document

When the real engine and this document disagree, the engine wins and this document is
corrected — then `engine-mock.js` is updated to match, because it is the executable
statement of what is written here.
