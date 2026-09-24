# Curriculum

The teaching arc, one drill track per generation plus a defender track. Each drill runs a
real attack against a real (simulated) air in the engine and awards a flag only when the
engine's own state satisfies a predicate — see DESIGN.md's "rule that makes drills
trustworthy." There are no hardcoded answer strings; a flag is never captured by a UI label
changing, only by the world actually reaching that state. See `DESIGN.md` section 2 for the
full protocol scope this outline draws from, and `site/ENGINE-API.md` for the snapshot shape
every drill below renders from.

The single question the whole arc answers, one generation at a time: **can the phone tell a
real network from a fake one, and can an eavesdropper recover the permanent identity that
names the human carrying the phone?** 2G answers "no" to both. 4G fixes the second half for
anyone who finishes the handshake, but not before it starts. 5G fixes the leak itself — when
the fix is actually turned on. The defend track shows the same evidence from the other side
of the glass.

---

## Track 1 — 2G / GSM: broken by design

2G's failure is structural, not a bug: the standard never asked the network to prove itself,
and it made encryption a network choice instead of a floor.

### Catch an IMSI on 2G — `gsm-2g-imsi-catch`

- **Teaches:** one-way authentication. A3/A8 lets the *network* verify the phone via
  RAND → SRES/Kc; nothing in GSM lets the *phone* verify the network. A cell that simply
  out-shouts the real one (stronger broadcast signal, same PLMN) gets the phone to camp on
  it, and from there an Identity Request for the IMSI is just... answered. There is no
  protocol step where the phone could object.
- **What the learner does:** loads the drill (one legitimate cell, phone camped on it,
  nothing has happened yet), then runs the attack. The engine stands up a second, stronger
  cell announcing the same network id and steps the phone through reselection, an Identity
  Request, and the plaintext Identity Response.
- **What proves it:** the `imsi-in-hand` flag, which only captures once `ue.imsi_leaked` is
  `true` in engine state — i.e. the simulated IMSI actually crossed the simulated air in the
  clear, not because a button was clicked. The monitor separately raises a `High`
  `CleartextIdentityRequest` finding and a `Medium` `UnexpectedAreaCode` finding (the rogue
  cell's area code is the reserved maximum for its field width — a concrete, checkable tell,
  not a hand-wave).

### Turn off encryption — `gsm-2g-null-cipher`

- **Teaches:** the network — not the phone — picks the cipher (A5/1, A5/3, or A5/0/null),
  and 2G signalling has no integrity protection to stop a rogue network from picking A5/0.
  Once that command lands, the phone has no way to detect or refuse it.
- **What the learner does:** same rogue-cell setup as the IMSI drill (deliberately — it is
  the same infrastructure), but this time watches the sequence continue past the Identity
  Request into a Cipher Mode Command naming A5/0, and the phone's unconditional Cipher Mode
  Complete.
- **What proves it:** the `null-cipher-forced` flag captures on `ue.null_cipher_active`
  becoming `true`. The monitor raises a `High` `ForcedNullCipher` finding — the concrete,
  checkable claim being that everything after that point on that cell is unencrypted.

---

## Track 2 — 4G / LTE: mutual auth, and the gaps that survive it

EPS-AKA makes the network prove it holds the subscriber key K via AUTN. That closes the
headline 2G hole for anyone who reaches a completed authentication — but two gaps survive:
messages that travel *before* security exists, and what happens when the phone is told to
leave LTE entirely.

### Catch an IMSI on LTE — `lte-4g-imsi-catch`

- **Teaches:** a fake eNodeB cannot complete EPS-AKA — it doesn't hold a valid AUTN for the
  target's key. But it doesn't need to: on attach, if the phone's GUTI isn't recognised, the
  network sends an Identity Request for the IMSI *before* any security context exists, and
  the phone answers before authentication has even started. The headline attack is closed;
  this side door is not.
- **What the learner does:** watches the phone attach with its GUTI (deliberately avoiding
  ever sending the IMSI), get told the GUTI isn't recognised, and hand over the IMSI anyway.
- **What proves it:** `imsi-in-hand` on `ue.imsi_leaked`, exactly as in the 2G drill — this is
  the point of contrast: **the same flag, the same field, a completely different-looking
  network underneath.** The monitor's `CleartextIdentityRequest` finding is identical in kind
  to the 2G one, because it is the same underlying weakness (a pre-security cleartext
  identity request), just surviving into a generation that supposedly fixed authentication.

### Force a downgrade to 2G — `lte-4g-downgrade`

- **Teaches:** Attach Reject, TAU Reject, and RRC Connection Reject all travel before
  integrity protection is established, so the phone cannot verify one actually came from a
  trustworthy source. A rogue eNodeB can reject the attach with a cause that tells the phone
  not to try LTE here at all — and the phone, playing by the rules, falls back to whatever
  RAT is left. If that's GSM, every Track 1 attack is available again.
- **What the learner does:** watches a rogue LTE cell reject the attach, watches the phone
  disable LTE and reselect to GSM, and watches a rogue GSM cell (the *same* attacker's
  infrastructure) catch the IMSI there.
- **What proves it:** the `downgrade-forced` flag captures on the phone actually ending up
  camped on GSM (`ue.camped_rat === 'gsm'`) with the identity leaked. The monitor raises four
  findings in sequence — the unprotected reject, the forced RAT downgrade, the resulting
  cleartext IMSI, and a correlation finding that both the LTE and GSM rogue cells shared the
  same reserved area-code value, which is the kind of cross-cell evidence a real analyst uses
  to tie two sightings to one piece of rogue hardware.

---

## Track 3 — 5G / NR: SUCI as the fix, and its remaining seams

5G's answer to the IMSI-catcher problem is to stop sending the permanent identifier in the
clear at all. SUCI encrypts the SUPI with the home network's public key (ECIES Profile A)
before it ever reaches the air. This is the exact structural parallel to OSDP fixing
Wiegand's plaintext card data in Open Door Range: the fix works, and it is also optional.

### SUCI does its job — `nr-5g-suci-protects`

- **Teaches:** the fix, working. This drill deliberately mirrors the 2G and 4G IMSI-catch
  drills move for move — rogue cell, stronger signal, reselection, Identity Request — right
  up until the response. Where the earlier generations hand back a plaintext IMSI, the 5G
  phone hands back a SUCI: ciphertext the rogue network cannot decrypt because it does not
  hold the home network's private key.
- **What the learner does:** runs the identical attack shape as the 2G/4G drills against a 5G
  phone, and watches it fail to recover anything readable.
- **What proves it — and this is the flag that matters most in the whole arc:** the
  `suci-holds` flag does **not** check that an attack succeeded. It checks that the attacker
  actually tried (a rogue cell stood up, an Identity Request was sent, an Identity Response
  came back) and that `ue.imsi_leaked` is still `false`. The monitor reflects this
  asymmetry too: no `High` finding here — only an `Info`-level `ConcealedIdentityResponse`
  (nothing to name a subscriber) and a `Low`-level `SuspiciousCellPresent` (the odd cell
  itself is still visible to a monitor, which is worth watching, but is not proof of a
  successful identity attack). Compare this finding list side-by-side with the 2G drill's
  `High` `CleartextIdentityRequest` — that contrast **is** the drill.

### Undo SUCI with the null scheme — `nr-5g-null-scheme`

- **Teaches:** SUCI's protection is a configuration choice, not a law of physics. Protection
  Scheme 0 — the null scheme — is legal per spec and sends the SUPI inside a SUCI-shaped
  message with no encryption applied. A network (or a subscriber profile) still configured
  this way defeats the entire point of concealment while remaining fully standards-compliant.
- **What the learner does:** runs the same rogue-cell attack as the previous drill, but
  against a profile using the null scheme, and watches the "concealed" response turn out to
  be readable.
- **What proves it:** the `supi-in-hand` flag captures on `ue.imsi_leaked` becoming `true`
  again (the frozen snapshot contract has one field for "the permanent identifier leaked in
  the clear" — it does the same job whether the generation calls that identifier an IMSI or a
  SUPI; see `docs/UI.md` for why this is a deliberate, non-breaking reading of the contract,
  not a new field). The monitor raises a `High` `NullProtectionSchemeSuci` finding, explicit
  that this is a legal configuration, not a bug in SUCI itself.

---

## Defender track

`ocr-detect` is first-class, not an afterthought: for every attack the range can run, a
passive monitor states what a Rayhunter-class detector would conclude from the same air. This
track puts the learner in the monitor's seat directly.

### Spot the catcher — `defend-spot-the-catcher`

- **Teaches:** defenders don't get to watch attacks happen in real time; they arrive after
  the fact and have to reconstruct what happened from the air log alone. This drill is the
  deliberate exception to every other drill's structure: nothing changes in the world when
  the learner clicks the button. The attack (a rogue LTE cell, a reselection, a cleartext
  IMSI response) already happened before the drill loaded. The button is labelled **Run the
  monitor**, not *Run the attack* — because that is what it actually does.
- **What the learner does:** reads the pre-populated air log (cells, events, the phone's
  current state) with no findings yet shown, forms a hypothesis about what happened, then
  runs the passive monitor over that same log.
- **What proves it:** the `catcher-flagged` flag captures once the monitor has actually run
  and produced its findings — a `High` `CleartextIdentityRequest`, a `Medium`
  `UnexpectedAreaCode` naming the specific reserved value observed, and a `Low`
  `ImplausibleSignalStrength` noting that −41 dBm is stronger than a macro cell typically
  achieves outdoors. **Map each finding back to the attack that caused it:** the cleartext
  request is Track 1/2's headline weakness surviving onto whatever RAT the phone was on when
  it happened; the area-code anomaly and the implausible signal are the same "be the
  strongest cell, and don't bother configuring realistic broadcast parameters" tell that
  every catcher drill in this curriculum shares. That shared tell is deliberate: a learner who
  has done the attack drills first should recognise it immediately from the defender's side.

---

## Reading the arc as one story

| Drill | Generation's fix | The gap that survives | Flag |
|---|---|---|---|
| Catch an IMSI on 2G | *(none — this is the baseline)* | No mutual auth, no integrity | `imsi-in-hand` |
| Turn off encryption | *(none)* | Network picks the cipher, unilaterally | `null-cipher-forced` |
| Catch an IMSI on LTE | Mutual auth (EPS-AKA) | Pre-security Identity Request is unprotected | `imsi-in-hand` |
| Force a downgrade to 2G | Mutual auth | Pre-auth reject messages are unprotected | `downgrade-forced` |
| SUCI does its job | SUCI conceals the SUPI | *(the fix holds — shown deliberately)* | `suci-holds` |
| Undo SUCI with the null scheme | SUCI | Null protection scheme is spec-legal | `supi-in-hand` |
| Spot the catcher | *(defender side)* | — | `catcher-flagged` |

A workshop or classroom run works well in this exact order: it reproduces the historical
argument (2G is broken; 4G fixes the headline case but not the whole thing; 5G finally fixes
the leak itself, but only if you turn it on) and ends on the defender track, which asks the
learner to recognise everything they just did to a phone from the other side of the glass.
