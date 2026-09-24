# Detection reference

The defender's cheat sheet: for every attack the range teaches, what it looks like on the air
and what a passive monitor — `ocr-detect`'s `Monitor` — actually concludes from it. This mirrors
`docs/CURRICULUM.md`'s drill order and `docs/PROTOCOL.md`'s protocol detail; read this one for
"what would my own detector say if it saw this."

**The constraint that makes this honest:** `Monitor` sees only the [`AirEvent`] stream — the same
messages a real receiver would decode off the air — and never the simulation's internal
`legitimate` flag that marks which cell is actually the rogue one. Every conclusion below is
something a real passive detector, fed a real capture, could also reach from the same evidence.
That is deliberate and is the entire point of shipping `ocr-detect` as a first-class part of the
project rather than an answer key: **this is the same reasoning Rayhunter uses** against real
capture data, phrased over a simulated capture instead. If you can read this document, you can
read what Rayhunter tells you about your own environment.

A severity is not a verdict. Every entry below states plainly whether a finding is a strong tell
or one that also happens for innocent reasons — a detector (real or simulated) that cries wolf
on ordinary network behaviour teaches the wrong lesson, and `ocr-detect`'s own heuristics are
deliberately written to fire on the low-false-positive shape of each signal rather than the
broadest possible one.

---

## 1. Per-attack: what the attacker does, what's on the air, what the monitor concludes

### Track 1 — 2G / GSM

#### Catch an IMSI on 2G (`gsm-2g-imsi-catch`)

| | |
|---|---|
| **Attacker does** | Stands up a second cell on the same PLMN with a stronger broadcast signal than the real one, waits for the phone to reselect, then sends an `IdentityRequest(IMSI)`. |
| **On the air** | A `LocationUpdateRequest`, an `IdentityRequest` naming `IMSI`, an `IdentityResponse` carrying the IMSI in the clear — all before any authentication challenge is even attempted. |
| **Monitor concludes** | **`CleartextIdentityRequest` — High.** The permanent identity was requested (and answered) with no protected security context in place. |

The finding fires on the *request*, not on proof the attacker was malicious — see §2's entry for
why that's deliberate. If the rogue cell also broadcasts a reserved LAC/cell-id value (a common
tell for hastily-configured rogue hardware — see §2's `UnexpectedCellIdentity`), that fires too,
independently, the first time that cell's `SystemInformation` is observed.

#### Turn off encryption (`gsm-2g-null-cipher`)

| | |
|---|---|
| **Attacker does** | Same rogue-cell setup, but continues past the identity request into a `CipherModeCommand` naming `A5/0`. |
| **On the air** | A `CipherModeCommand{algorithm: A5_0}` followed by the phone's unconditional `CipherModeComplete` — the phone has no protocol mechanism to refuse. |
| **Monitor concludes** | **`NullCipherCommanded` — High.** Everything on this cell from this point forward is unencrypted. |

### Track 2 — 4G / LTE

#### Catch an IMSI on LTE (`lte-4g-imsi-catch`)

| | |
|---|---|
| **Attacker does** | Stands up a rogue eNodeB; the phone attaches with a GUTI (never its IMSI) the rogue network doesn't recognise, so it sends a NAS `IdentityRequest` before any security context exists. |
| **On the air** | `AttachRequest{guti}` → `IdentityRequest` → `IdentityResponse{imsi}`, all pre-security — structurally the same shape as the 2G drill, on a completely different generation underneath. |
| **Monitor concludes** | **`CleartextIdentityRequest` — High.** The exact same finding kind, same severity, as the 2G drill. That's not a coincidence in the code — it's the same weakness (a pre-security cleartext identity request) surviving into a generation that fixed the *other* headline 2G problem. |

Mutual authentication being intact on this cell (if the attacker even attempts it — a keyless
attacker can't, and doesn't need to) does not retroactively protect an identity that already
crossed the air before authentication ran.

#### Force a downgrade to 2G (`lte-4g-downgrade`)

| | |
|---|---|
| **Attacker does** | Rejects the LTE attach with an unauthenticated `AttachReject`, then — once the phone falls back and reselects to GSM — runs the same rogue-BTS IMSI catch there with a second piece of infrastructure. |
| **On the air** | An `AttachReject` before any security context, the phone's RAT dropping from `lte` to `gsm`, then the Track 1 GSM sequence. |
| **Monitor concludes** | Four separate, independent findings, in order: **`UnprotectedReject` — High** (the reject itself — unauthenticated, so anyone could have spoofed it); **`ForcedDowngrade` — High** (specifically because the landing RAT is GSM — dropping to the broken-by-design generation is the worst case this finding distinguishes); **`CleartextIdentityRequest` — High** once the phone is on the rogue GSM cell; and, if both rogue cells share a broadcast tell (e.g. the same reserved LAC/TAC value), two separate **`UnexpectedCellIdentity` — Medium** findings, one per cell. |

Worth being precise about that last point: `Monitor` raises `UnexpectedCellIdentity`
**per cell**, the first time each one is observed — it does not itself produce a single
"these two cells are the same attacker's infrastructure" finding. Noticing that two independently-
raised findings name the *same* implausible value is a correlation step an analyst adds on top of
the raw findings list, not something the monitor concludes on its own. That's a genuine and
useful limitation to know about your own tooling: a findings list is not automatically a
narrative, even when the narrative is obvious to a human looking at both lines at once.

### Track 3 — 5G / NR

#### SUCI does its job (`nr-5g-suci-protects`)

| | |
|---|---|
| **Attacker does** | Runs the identical attack shape as the 2G/4G IMSI-catch drills — rogue cell, stronger signal, reselection, identity request — against a 5G phone using a real protection scheme. |
| **On the air** | A rogue cell, a `RegistrationRequest`, an `IdentityRequestSuci`, an `IdentityResponseSuci` carrying a Profile-A-protected SUCI the attacker cannot open. |
| **Monitor concludes** | **Nothing.** Literally zero findings. A protected SUCI registration is indistinguishable, to this monitor, from a normal clean attach — there is no plaintext identity for `CleartextIdentityRequest` to catch, because 5G's NAS identity-request message asks for a SUCI in the first place, not a bare SUPI. |

This silence *is* the finding, and it's worth stating plainly rather than dressing it up: the
whole point of this drill is that the same attack infrastructure, run against a generation that
turned the fix on, produces nothing for a monitor to say. Compare this directly against the 2G/4G
drills' `High` `CleartextIdentityRequest` — that contrast, not any particular alarm, is the
lesson. (If you're running a live monitor over a real capture and see genuinely nothing during
what looks like a suspicious cell sighting, that is consistent with either "nothing happened" or
"something happened and the protection held" — see §3's closing note on what silence does and
doesn't prove.)

#### Undo SUCI with the null scheme (`nr-5g-null-scheme`)

| | |
|---|---|
| **Attacker does** | Runs the same attack against a profile configured to use the null protection scheme — a legal, spec-permitted configuration. |
| **On the air** | The same `RegistrationRequest`/`IdentityResponseSuci` shape, but the SUCI's `scheme` field is `Null` and its "concealed" payload is the MSIN verbatim. |
| **Monitor concludes** | **`NullSuciScheme` — High.** The monitor checks `suci.is_protected()` on any SUCI it sees, whether in a `RegistrationRequest` or an `IdentityResponseSuci` — either message triggers the same finding. The wording is deliberately explicit that this is a **legal configuration**, not a bug in SUCI itself: the cryptography works exactly as designed; the deployment simply turned it off. |

### Defender track

#### Spot the catcher (`defend-spot-the-catcher`)

This drill inverts the framing on purpose: nothing changes in the world when the button is
clicked — the attack already happened, and the button (labelled **Run the monitor**, not *Run the
attack*) replays the passive analysis over an air log that's already fixed. This is the realistic
case: a defender arrives after the fact and reconstructs what happened from a log, not from
watching it live. Whatever combination of findings the underlying rogue-cell/cleartext-IMSI
sequence produces (the same `CleartextIdentityRequest`, and any cell-identity findings the
particular scenario's rogue broadcast triggers) is what "spotting the catcher" actually means in
practice: running the same `Monitor` this document describes over a log you didn't watch happen,
and trusting only what its findings actually say — not a guess about what you think you'd have
seen.

---

## 2. Finding-kind reference

Every kind `Monitor` can emit, in the order declared in `ocr-detect::FindingKind`, with its
severity, what specifically triggers it, and — the part that matters most for teaching — what
else, entirely innocent, can trigger the identical signal.

| Finding | Severity | Strong tell, or ambiguous? | Also happens benignly when… |
|---|---|---|---|
| **`CleartextIdentityRequest`** | High | Ambiguous by design | A genuine first attach with no valid temporary id at all also triggers this — the finding means *the permanent identity was exposed*, not *an attack occurred*. On 2G/4G this is unavoidable even for honest networks; only 5G's SUCI-based request removes the ambiguity by removing the plaintext path entirely. |
| **`NullCipherCommanded`** | High | Mostly strong | A5/0 / EEA0-EIA0 / NEA0-NIA0 are legal for unauthenticated emergency calls. On an ordinary subscriber attach, a null cipher is a strong tell — Rayhunter's flagship heuristic for exactly this reason. |
| **`ForcedDowngrade`** | High (landing on GSM) / Medium (otherwise) | Ambiguous, severity does the work | Dropping a generation is completely ordinary in poor coverage. The severity split exists because the *destination* matters: landing on GSM specifically strips the subscriber back to the one-way-auth, optionally-null-cipher generation — the exact goal of a bidding-down attack — while dropping only as far as, say, NR→LTE is a much smaller loss and stays Medium. |
| **`UnexpectedCellIdentity`** | Medium | Strong, checkable | A conforming cell never broadcasts a reserved LAC/TAC/cell-id (`0x0000`, the reserved maxima, or the RAT's "not yet assigned" value). This one has essentially no benign cause — it's a configuration error real hardware doesn't make by accident, which is exactly why hastily-deployed rogue gear trips it. Fires only on a cell's *first* sighting, so a periodic rebroadcast of the same bad value doesn't spam the findings list. |
| **`LocationAreaJumped`** | Medium | Strong for what it checks | The *same* opaque cell later claiming a different area code/PLMN/cell-id for its own broadcast. A fixed physical cell's identity is stable; reselecting between two genuinely different real cells with different area codes is ordinary and is deliberately **not** this finding — it only fires on one cell's identity changing out from under it, which is the actual anomaly and the leading source of false positives if it weren't scoped this tightly. |
| **`AuthenticationNeverCompleted`** | Medium | Ambiguous | Fires when an auth challenge went out and the UE reselected away before ever reaching a protected security context. A genuine network can also abandon an attach mid-flight (congestion, a legitimate reject). But it's also exactly the shape of a fake cell that issues a challenge it can't actually validate a response to and gives up. |
| **`ImplausibleSignalStrength`** | *(reserved; never emitted)* | — | `AirEvent` carries no signal-strength field, so nothing in this stream can compute this today. The kind exists for API stability and the future capture/replay seam, not because the current engine models it — see the note below. |
| **`RejectStorm`** | Medium | Strong as a pattern, weak as a single event | A single unprotected reject is unremarkable — networks legitimately reject attaches. Three or more **unprotected** rejects within a 10 (virtual) second window is not; that's `REJECT_STORM_WINDOW_US`/`REJECT_STORM_THRESHOLD` in the source, both concrete and checkable against a capture. Latched so one storm reports once rather than re-firing every subsequent reject in the window. |
| **`NullSuciScheme`** | High | Strong | A SUCI whose `scheme` is `Null` is, definitionally, the SUPI in the clear (TS 33.501 Protection Scheme 0) — there's no ambiguous case here the way there is for a first-attach cleartext IMSI request; a null-scheme SUCI is always a full identity exposure, whatever the reason it's configured that way. |
| **`UnprotectedReject`** | High | Ambiguous, and that's the danger | `AttachReject`/`TAU Reject`/RRC/NR `Reject` before any security context exists. These are, by construction, unauthenticated — anyone can spoof one. A lone congestion reject from a real network looks *identical* on the wire, which is precisely why this class of message is dangerous: the LTEInspector/aLTEr bidding-down lever works exactly because the phone has no way to tell the two apart either. An integrity-protected reject *after* security is up is trustworthy and is deliberately never flagged. |
| **`NetworkAuthenticationFailed`** | High | Strong | The UE reported a MAC failure — the far side's `AUTN` didn't verify under the subscriber's real key. A legitimate network, which holds the real key, essentially never produces this; the only benign cause is a transient bit error, and that's non-repeating. A keyless fake cell attempting AKA fails here every time. |
| **`ImsiPaging`** | Medium | Fairly strong | Paging by the permanent identity rather than a temporary one. A well-behaved network pages by S-TMSI/5G-TMSI; IMSI paging is the ToRPEDO/PIERCER presence-confirmation pattern — an attacker (or a misconfigured network) using the permanent id to page specifically confirms a target is in the cell. |
| **`LinkabilityProbe`** | Low | Weak alone, meaningful as a pattern | Both a MAC failure *and* a sync failure observed on the same RAT session. A normal attach produces at most one failure type; seeing both is consistent with the AKA failure-message oracle being actively exercised (replaying a captured `AUTN` to test whether it belongs to a target). Kept Low because ordinary SQN drift (e.g. a SIM used across multiple devices) can also produce a sync failure on its own — it's the *combination*, not either failure alone, that's the tell, and even the combination is not proof. |

### A gap worth being upfront about: signal strength

`docs/CURRICULUM.md`'s defender-track narrative describes an implausibly strong signal
(`−41 dBm`, stronger than a macro cell typically achieves outdoors) as part of what the monitor
flags in `defend-spot-the-catcher`. The actual `AirEvent` stream this `Monitor` consumes carries
no signal-strength field at all — `ImplausibleSignalStrength` exists in the `FindingKind` enum for
API stability and the future hardware-capture seam, but nothing in the current engine can trigger
it. If you're teaching from a live run of the drill, the signal-strength anomaly is real *in the
world* (a rogue cell that out-shouts the real one *is* how cell reselection is won — see
`docs/PROTOCOL.md` §3), but it currently shows up in the scenario's narrative framing and the
world state a learner can inspect directly, not as a line in the monitor's own findings list. This
is worth surfacing to a workshop group as its own lesson: **a real detector's honesty about what
it can and cannot see is itself something to check, not assume** — the same discipline this whole
document asks of a defender applies to the defender's own tooling too.

---

## 3. What you can, and can't, conclude from the air

- **A finding is evidence, not a verdict.** Half the table above is "ambiguous" for a reason:
  `CleartextIdentityRequest`, `ForcedDowngrade`, `AuthenticationNeverCompleted`, and
  `UnprotectedReject` all have real benign causes. Treat every `High` the same way you'd treat a
  strong indicator in any other domain — worth acting on, not worth treating as proof of intent
  on its own.
- **Absence of a finding is not absence of an attack.** The clearest example in this whole range
  is `nr-5g-suci-protects`: a real attack was attempted, in full, against a phone that happened to
  be protected, and the monitor says nothing at all. A quiet findings list from a real capture
  means "nothing this monitor's heuristics catch happened," not "nothing happened." A more capable
  attacker, or a gap this particular heuristic set doesn't cover, produces the same silence.
- **The monitor sees the air, not intent.** It never has access to which cell is "really" the
  rogue one — only what a receiver could have decoded. Every conclusion in this document is
  reachable from the observable stream alone, which is exactly the constraint a real Rayhunter-
  class detector operates under against a real capture. That's a feature, not a limitation to work
  around: it's what makes the reasoning here portable to a real deployment instead of being an
  artifact of the simulation knowing more than it should.
- **Correlation across findings is your job, not the monitor's.** As the downgrade drill shows,
  the monitor raises independent, per-cell findings; connecting "these two cells both used the
  same implausible broadcast value" into "this is one piece of rogue hardware operating on two
  RATs" is an analyst step layered on top of the raw list.
- **A quiet log from a real device is a starting point for a question, not an answer.** If you run
  this same reasoning against a real Rayhunter capture and get silence, the next question is
  whether your device's air time genuinely had nothing to flag, or whether the environment you
  were in simply wasn't hostile during that capture window — the same distinction that separates
  `nr-5g-suci-protects`'s "the fix held" from "nothing happened to test it."
