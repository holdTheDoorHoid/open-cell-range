# Open Cell Range — design

**Authoritative spec.** Read this before touching code. Decisions marked **DECIDED** came
from the owner and must not be changed without asking. This is the cellular sibling of
[Open Door Range](https://github.com/holdTheDoorHoid/open-door-range) and deliberately
mirrors its architecture so the two form one product family with shared tooling.

## 1. What this is

A browser-based virtual range for cellular network attacks. You get a simulated radio
world — a phone (UE) that camps on cell towers, base stations that broadcast and page,
and a core network that authenticates — which you can watch, tap, and attack, plus guided
drills that drive that same simulation. No SDR, no radio, no SIM. It runs entirely in a
browser tab.

It exists because learning how IMSI catchers and cell-site simulators actually work
currently requires an SDR, a shielded room to stay legal, and enough RF knowledge to not
brick your understanding on the first misconfiguration. That gate keeps the subject in the
hands of people who already have a lab. The range removes the gate — and pairs with
[Rayhunter](https://github.com/EFForg/rayhunter), which detects these attacks in the real
world.

**DECIDED — audience is both, in layers.** A beginner follows a guided course and is never
lost. A practitioner ignores the course, opens the sandbox, and has a real tool:
message-level inspection of NAS and RRC, a cell composer, key and identifier management,
and a passive-monitor view that mirrors what a real detector concludes.

## 2. Scope

**DECIDED — the full 2G → 4G → 5G arc.** The arc is the whole point. Each generation is a
chapter in one story about a single question: *can the phone tell a real network from a
fake one, and can an eavesdropper recover the permanent identity that names the human
carrying the phone?*

### Track 0 — the identity and the air
The thing every attack is ultimately about is an identifier that names a subscriber.
- Permanent identifiers: **IMSI** (2G/4G) and **SUPI** (5G); the IMSI decomposes into
  MCC + MNC + MSIN.
- Temporary identifiers meant to keep the permanent one off the air: **TMSI**, **P-TMSI**,
  **GUTI** / **S-TMSI** (4G), **5G-GUTI** (5G).
- **SUCI**: the 5G Subscription Concealed Identifier — the SUPI encrypted with the home
  network's public key before it ever crosses the air. This is the fix the whole arc
  builds toward.
- The air layer: cells (BTS / eNodeB / gNodeB), the broadcast (system information), **cell
  selection and reselection driven by signal strength**, PLMN selection, and paging. Every
  catcher on earth pulls the same lever — *be the strongest cell on the target's network* —
  so the selection logic is modelled honestly, not hand-waved.

### Track 1 — 2G / GSM: broken by design (the "Wiegand" of cellular)
- **One-way authentication.** The network authenticates the phone (A3/A8 over
  RAND → SRES/Kc); the phone never authenticates the network. This is the original sin the
  next two generations spend their whole design budget trying to undo.
- **Encryption is optional and network-selected.** A5/1, A5/3, or **A5/0 (null)**, and the
  network picks. A fake base station simply commands A5/0.
- **No integrity protection on signalling.**
- Attacks modelled: rogue BTS out-signals the real one → phone camps → **Identity Request
  (IMSI)** hands over the permanent id in plaintext; **forced A5/0**; **location tracking**
  via LAC/CI; and the classic **relay MITM** to the real network.

### Track 2 — 3G / 4G LTE: mutual auth, and the gaps that survive it
- **EPS-AKA is mutual.** The network now proves it knows the subscriber key K via
  **AUTN** (RAND, SQN⊕AK, AMF, MAC). A naive fake eNodeB can no longer complete
  authentication. Headline fake-BTS IMSI grab: closed. Except:
- **IMSI is still requested in cleartext before the security context exists.** On attach
  with an unknown/absent GUTI, the network sends **Identity Request (IMSI)** and the phone
  answers before AKA runs. So a fake eNodeB still catches IMSIs — it just cannot then serve
  traffic.
- **Pre-authentication messages are unprotected.** Attach Reject, TAU Reject, RRC
  Connection Reject, Identity Request, and capability/measurement messages travel before
  integrity is on — the LTEInspector / aLTEr family. Result: **bidding-down** (force a
  drop to 2G, where Track 1 applies), targeted DoS, and capability leaking.
- **Paging and location:** IMSI/S-TMSI paging, the ToRPEDO/PIERCER class of paging-occasion
  side-channels that confirm a target is in a cell.

### Track 3 — 5G NR: SUCI as the fix, and its remaining seams (the "OSDP" of the story)
- **SUCI concealment.** The SUPI is encrypted with the home network's public key
  (**ECIES**, Profile A over Curve25519) before transmission. The plaintext-identity
  request that powered every prior attack is finally dead. *This is the exact structural
  parallel to OSDP fixing Wiegand in Open Door Range.*
- **But the fix is optional and downgradable, and the quiet weaknesses survive** — which is
  the more interesting teaching material, exactly as the Mellon medium/low findings are in
  Open Door Range:
  - **Null-scheme SUCI (Protection Scheme 0)** sends the SUPI in the clear and is a legal,
    spec-permitted configuration.
  - **Downgrade** to 4G/2G still works whenever the UE is allowed to fall back.
  - **Linkability side-channels:** the AKA failure messages distinguish MAC-failure from
    synchronisation-failure, which leaks whether a captured `AUTN` belongs to a given
    subscriber; SUCI/`AUTS` replay linkability; and 5G-GUTI reallocation that is too
    infrequent, so the "temporary" id is durable enough to track.
  - **Traffic analysis survives concealment**, the way OSDP's plaintext command byte does:
    paging and connection patterns still reveal *when* a known subscriber is present.

### The defensive half is first-class
`ocr-detect` is not an afterthought. For every attack the range can run, the passive
monitor states what a **Rayhunter-class detector** would conclude from the same air:
an unexpected cell identity, a LAC/TAC that jumped, a forced downgrade when a better RAT
was available, a null cipher command, a cleartext IMSI request, an authentication the
network could not complete, implausible signal strength, or a reject storm. The point of
the project is that a defender runs the *same* range and learns what their own environment
looks like under each attack.

## 3. Architecture

**DECIDED — one Rust engine, compiled to WebAssembly for the site.** The reason is not
language preference: it means the teaching simulation and the real-capture analyser are
literally the same code, so a drill can never teach something the analyser disagrees with.
The same crates build a command-line tool.

```
open-cell-range/
  crates/
    ocr-crypto/    the shared cryptographic primitives, all deterministic and no_std:
                   MILENAGE (f1..f5, f1*, f5*) for AKA vectors, ECIES SUCI Profile A,
                   AES/CTR/CMAC wrappers, a SEEDED deterministic RNG. No OS entropy.
    ocr-identity/  identifiers: IMSI/SUPI (MCC/MNC/MSIN), TMSI/GUTI/5G-GUTI, and SUCI
                   conceal/deconceal (null scheme + Profile A) built on ocr-crypto
    ocr-gsm/       2G: A3/A8/A5, RAND/SRES/Kc, cipher-mode command, Identity Request,
                   LAC/CI, the one-way-auth and null-cipher paths
    ocr-lte/       4G: EPS-AKA (RAND/AUTN/RES/K_ASME/SQN/MAC), the NAS + RRC message
                   subset, Security Mode Command, attach/TAU, paging, pre-auth rejects
    ocr-nr/        5G: 5G-AKA, SUCI-based attach, null-scheme allowance, downgrade
                   permissions, the failure-message and reallocation linkability seams
    ocr-air/       the virtual RF medium and state machines: cells of each RAT, signal
                   strength and cell selection/reselection, UE and network actors, paging,
                   and taps for sniff / inject / rogue-cell. The odr-bus analogue.
    ocr-attack/    attacker actors: imsi-catch, downgrade/bidding-down, null-cipher force,
                   relay MITM, paging linkability, suci-null downgrade
    ocr-detect/    the defensive monitor: what a passive Rayhunter-class listener concludes
    ocr-scenario/  drill definitions and flag predicates, data-driven
    ocr-wasm/      the wasm-bindgen surface the site talks to
    ocr-cli/       phase-two seam: load a capture, replay it through the same engines
  site/            static HTML/CSS/JS, no framework, no build step of its own
  docs/            protocol reference, curriculum, ethics note, UI notes
```

### The rule that makes drills trustworthy

**Drills do not describe attacks. They run them.** A drill step is a scenario executed by
the engine, and a flag is earned when the engine's own state satisfies a predicate — the
attacker actually recovered the IMSI, the UE actually camped on the rogue cell, the
network actually commanded A5/0. There are no hardcoded answer strings to check against.
If the engine is wrong, the drill fails rather than lying.

### Determinism (the hard constraint every crate obeys)

A virtual microsecond clock drives everything. **No wall-clock time. No OS randomness.**
The tricky part is that AKA and ECIES *require* randomness — RAND challenges, ECIES
ephemeral keys. Those come from a **seeded deterministic RNG in `ocr-crypto`**, threaded
explicitly through every call that needs entropy. The same scenario and seed always
produce the same bytes on the wire, so flags are stable, bugs are reproducible, and a
capture replays identically on any machine. Every crate is `#![no_std]` + `alloc` with an
optional `std` feature that only adds `std::error::Error` impls; this is what forces the
"no clocks, no threads, no OS entropy" discipline and guarantees a clean
`wasm32-unknown-unknown` build. `ocr-cli` and `ocr-wasm` are the only crates that may use
`std`.

### No real secrets, no real spectrum

Subscriber keys are the **published 3GPP test-vector K values** (TS 35.207/35.208 for
MILENAGE, TS 33.501 Annex C for SUCI), never real ones. The virtual air is a data
structure in memory; nothing is ever transmitted. This is what makes the range safe to
ship and safe to run anywhere — see `docs/ETHICS.md`.

### Capture format (the phase-two seam)

**DECIDED — hardware capture import is phase two, but the seam is designed now.**
Newline-delimited JSON, one line per observed message:

```
{"t_us": 12345,
 "rat": "gsm" | "lte" | "nr",
 "chan": "bcch" | "ccch" | "pch" | "dcch" | "nas" | "rrc",
 "dir": "net_to_ue" | "ue_to_net" | "observed",
 "cell": "<opaque cell id>",
 "arfcn": 512,            // earfcn for lte, nrarfcn for nr; the field name follows the rat
 "msg": "<message type name>",
 "bytes": "0102ab..."}
```

`ocr-cli` reads it today. Importers for **Rayhunter's own capture output**, **SCAT**,
**QCSuper**, and **GSMTAP pcap** come later without touching the engines. Two rules,
fixed now so importers never have to guess:

- **`rat` is mandatory and authoritative.** Folding the generations together would lose the
  one fact an analyser most needs: which radio access technology recorded the message.
- **`msg` is the decoded type name when the writer knows it; `bytes` is always present.**
  A reader that does not recognise `msg` falls back to decoding `bytes` for that `rat`.

## 4. Product decisions

- **DECIDED — sandbox with drills layered on top.** One live radio world, always pokeable;
  the course drives that same world rather than a separate scripted mock.
- **DECIDED — CTF flags, local only.** Progress lives in the browser. No backend, no
  accounts, nothing collected about anyone who uses it. A village runs it competitively by
  having people show their screen.
- **DECIDED — online is fine.** Plain GitHub Pages. No offline packaging in v1.
- **DECIDED — GPLv3.** Copyleft keeps this from being absorbed into a closed vendor
  training product; it shares detector lineage with Rayhunter's world.
- **DECIDED — open source, business in workshops and hardware.** The range is free and
  open, exactly like Rayhunter. The revenue is LSOH workshops that teach with it, instructor
  material, and the SDR / capture hardware it pairs with for the phase-two real-capture
  work. Nothing in the codebase is paywalled.
- **DECIDED — the name is Open Cell Range.**

## 5. Ethics posture

Everything here is simulated. No real credentials, no carrier-specific exploit code, no
targeting of a named network, no transmitter of any kind. Subscriber keys are the
already-published 3GPP test vectors. The attacks modelled are the ones documented in the
public research and standards literature (the GSM one-way-auth problem, LTEInspector /
aLTEr pre-auth weaknesses, the 5G-AKA linkability papers). The defensive half `ocr-detect`
is a first-class part of the project: the point is that a defender can run the same range
and learn what their own air would look like under each attack. See `docs/ETHICS.md`.

## 6. Build order

1. Workspace, licence, CI, Pages skeleton, `ocr-crypto` primitives with test vectors.
2. `ocr-identity` — identifiers and SUCI, unit-tested against TS 33.501 Annex C vectors.
3. `ocr-gsm`, `ocr-lte`, `ocr-nr` — the three generations, each against known vectors.
4. `ocr-air` — cells, selection, UE/network state machines, taps.
5. `ocr-attack` and `ocr-detect`.
6. `ocr-scenario` and the drill content.
7. `ocr-wasm` and the site.
8. Pages deploy.

## 7. Crate contracts (frozen interfaces for parallel work)

These are the public seams other crates and the site build against. An implementer fills
in bodies and adds private items freely; **changing a public signature here means telling
the integrator, because something downstream is already compiled against it.** The exact
signatures live in each crate's `src/lib.rs` stub with doc comments; this table is the map.

| crate | depends on | owns |
|-------|-----------|------|
| `ocr-crypto` | — | `Milenage`, `suci` (ECIES Profile A + null), `SeededRng`, AES/CMAC helpers |
| `ocr-identity` | crypto | `Imsi`, `Supi`, `Plmn`, `Tmsi`, `Guti`, `FiveGGuti`, `Suci`, conceal/deconceal |
| `ocr-gsm` | identity, crypto | `GsmMessage`, `GsmAuthVector`, A5 mode, `Bts`/`MobileStation` step fns |
| `ocr-lte` | identity, crypto | `LteNasMessage`, `LteRrcMessage`, `EpsAkaVector`, security context |
| `ocr-nr` | identity, crypto | `NrNasMessage`, `NrRrcMessage`, `FiveGAkaVector`, SUCI attach |
| `ocr-air` | identity, gsm, lte, nr | `Rat`, `Cell`, `Ue`, `Network`, `AirEvent`, `Tap`, `World::step` |
| `ocr-attack` | air, gsm, lte, nr, identity | `Attacker` actors, one per attack, driving a `World` |
| `ocr-detect` | air, gsm, lte, nr, identity | `Monitor`, `Finding`, severity, over an `AirEvent` stream |
| `ocr-scenario` | air, attack, detect | `ScenarioId`, `Scenario`, `build`, `Flag`, `FlagState` predicates |
| `ocr-wasm` | all | the `Engine` object in `site/ENGINE-API.md` |
| `ocr-cli` | air, scenario, detect | NDJSON capture load + replay |

The engine surface the site consumes is specified in `site/ENGINE-API.md`; the site is
built against `site/js/engine-mock.js`, a JavaScript reference implementation of that same
contract, so the front end can be developed without a Rust toolchain.
