# Protocol reference

The technical background behind every drill: the identifiers an attacker is after, and the
three authentication stories — one per generation — that this project models on the air. This
is the reference, not the tutorial; `docs/CURRICULUM.md` is the tutorial and points back here.

The single question every generation answers differently: **can the phone tell a real network
from a fake one, and can an eavesdropper recover the permanent identity that names the human
carrying the phone?** 2G answers no to both. 4G answers the first question but leaks the
identity anyway before it gets the chance to matter. 5G finally protects the identity itself —
when the protection is actually turned on.

---

## 1. The identifiers

Everything in this project is ultimately about one fact: a cellular identifier that names a
specific human being, and whether that identifier ever crosses the air where anyone with a
receiver can read it.

### 1.1 IMSI — the permanent identity, 2G/3G/4G

The **International Mobile Subscriber Identity** is a decimal string, at most 15 digits, built
from three parts:

```
IMSI = MCC (3 digits) + MNC (2 or 3 digits) + MSIN (the rest)
```

- **MCC** — Mobile Country Code (e.g. `310` = USA, `262` = Germany).
- **MNC** — Mobile Network Code, identifying the carrier within that country. Length varies by
  country (North American carriers mostly use 3 digits; most of the rest of the world uses 2).
  MCC + MNC together is the **PLMN**, the thing that names *a network*.
- **MSIN** — Mobile Subscriber Identification Number, the per-subscriber tail the home network
  assigns. This is the part that actually distinguishes one subscriber from another on the same
  carrier.

The IMSI is provisioned once, on the SIM, and does not change. That permanence is exactly what
makes it dangerous on the air: capture it once and you have named a person for as long as they
keep that SIM. Structured (`Imsi::parse` / `Imsi::to_digits` in `ocr-identity`) rather than
opaque, leading zeros preserved throughout — an MSIN of `001002086` is not the same string as
`1002086`, and getting that wrong silently corrupts every downstream lookup.

### 1.2 SUPI — the permanent identity, 5G

The **Subscription Permanent Identifier** is 5G's name for the same concept. In its common
IMSI-based form it carries the identical MCC/MNC/MSIN structure (3GPP writes it as
`imsi-<digits>`); a SUPI can also be a network-access-identifier (NAI, `user@realm`) form for
non-IMSI use cases, which this project does not model. The point of renaming IMSI to SUPI in the
5G specs was not cosmetic — it comes bundled with a new rule: *the SUPI must never cross the
radio interface unconcealed if it can be avoided.* That rule is SUCI (§1.4).

### 1.3 Temporary identifiers — keeping the permanent one off the air

Every generation also hands out a short-lived, locally-scoped identifier so that day-to-day
signalling (paging, location updates, service requests) doesn't have to use the permanent one at
all:

| Identifier | Generation | Structure | Reallocated by |
|---|---|---|---|
| **TMSI** / P-TMSI | 2G/3G | An opaque 32-bit value, locally scoped to one location/routing area | The VLR/SGSN, typically on every location update |
| **GUTI** (and its paging form, **S-TMSI**) | 4G | PLMN + MME Group ID + MME Code + M-TMSI | The MME, on attach/TAU |
| **5G-GUTI** | 5G | PLMN + AMF Region ID + AMF Set ID + AMF Pointer + 5G-TMSI | The AMF, on registration |

These exist precisely so that the phone never has to say its permanent identity just to do
routine business with a network it has already registered with. The catch, which recurs at every
generation: the temporary identifier only protects the permanent one on the *good* path. The
moment the network doesn't recognise the temporary id it was handed (a genuine first attach, a
cleared VLR/MME/AMF record, or — the attack case — a fake base station that was never issued one
in the first place and has no way to recognise anybody's), the fallback in every generation
through 4G is to ask for the permanent identity outright. 5G is the first generation where that
fallback request itself is protected (see §1.4). A temporary id's protection also depends on how
often it's rotated: reallocate it rarely enough and it becomes a durable pseudonym that tracks
someone just as well as the permanent id would, even though it never leaks a name directly — the
`FiveGGuti` doc comment in `ocr-identity` calls this out explicitly as a 5G teaching point.

### 1.4 SUCI — the fix

The **Subscription Concealed Identifier** is the SUPI encrypted with the home network's public
key before it is ever transmitted. This is the structural fix the whole arc builds toward: for
the first time, a base station that isn't the subscriber's real home network — including a rogue
one — cannot simply ask for the permanent identity and get a useful answer.

```
Suci = { plmn, routing_indicator, scheme, concealed }
```

- **`plmn`** and **`routing_indicator`** travel in the clear. They have to: the serving network
  needs to know which home network (and, via the routing indicator, which key at that home
  network) to route the authentication request to. This is not a privacy leak of the subscriber
  identity itself — PLMN and routing indicator identify a *network* and a *key selector*, not a
  person.
- **`scheme`** says how the MSIN was protected. There are two the range models:
  - **Protection Scheme 0 — Null.** No encryption at all; the "concealed" payload is the MSIN
    in the clear. Legal per spec (TS 33.501 Annex C.3.1 permits it, largely for the null-scheme
    fallback used by unauthenticated emergency calls), but if a network or subscriber profile is
    left in this mode generally, SUCI's entire protection is fiction. `ocr-crypto`'s `suci`
    module implements this as a literal passthrough — see `docs/DETECTION.md`'s
    `NullSuciScheme` entry for what a monitor concludes when it sees one.
  - **Protection Scheme 1 — Profile A.** ECIES over Curve25519 (TS 33.501 Annex C.3.4.1): an
    ephemeral X25519 key pair is generated per concealment, an ECDH shared secret is computed
    against the home network's provisioned public key, and an ANSI-X9.63 KDF (SHA-256, TS 33.501
    Annex C.3.2) stretches that shared secret into an AES-128 key, a 128-bit initial counter
    block, and a 256-bit HMAC key. The MSIN is encrypted with AES-128-CTR and authenticated with
    an 8-byte truncated HMAC-SHA-256 tag. The ephemeral public key, ciphertext, and tag all travel
    on the air; the shared secret never does, and only the home network's private key can
    reconstruct it. (Spec also defines **Profile B**, an equivalent scheme over a NIST curve;
    this project implements Profile A only, which is what most Profile-A-capable deployments
    actually use.) `ocr-crypto::suci` is validated against the **TS 33.501 Annex C.4 worked
    example** — a fixed home key pair, ephemeral key, ciphertext and MAC that must decrypt to a
    specific known MSIN — so the implementation is checked against a published, numeric answer,
    not just internal round-tripping.

The load-bearing property: **a keyless on-air observer recovers nothing from a Profile-A SUCI**
(`observer_recovers_supi` in `ocr-nr` returns `None`), but **recovers the entire SUPI from a
null-scheme one** with no cryptography at all — the null scheme's "ciphertext" *is* the plaintext
MSIN. That asymmetry, not any particular cipher choice, is the whole 5G identity story.

---

## 2. The arc: each generation fixes the last one's headline flaw

| Generation | Headline flaw it inherited | What it fixes | What survives |
|---|---|---|---|
| **2G / GSM** | *(the baseline — nothing came before it)* | — | One-way auth, network-chosen (and possibly null) cipher, no integrity protection at all |
| **4G / LTE** | 2G's one-way auth: the phone can't tell a real network from a fake one | **EPS-AKA**: the network proves it holds the subscriber key via `AUTN`, so the phone finally authenticates the network too | The permanent identity is still requested and answered *before* that authentication ever runs; pre-auth reject messages are unauthenticated |
| **5G / NR** | 4G's pre-auth cleartext identity request | **SUCI**: the permanent identity is encrypted before it ever reaches the air, so there is no plaintext identity left to request | The fix is a configuration choice (null scheme), it is downgradable, and the AKA failure messages still leak whether a given subscriber is present |

This is the same shape as a secure protocol replacing a broken one anywhere else: the successor
doesn't throw out the predecessor's mechanism wholesale, it closes the *specific* hole that
mattered most and inherits everything it didn't touch. (It's the exact structural parallel this
project's sibling, Open Door Range, draws between Wiegand and OSDP: OSDP fixes Wiegand's
plaintext card data in the clear, and OSDP's own optional/downgradable security settings are
where the interesting remaining attack surface lives. 5G-AKA/SUCI is cellular's version of that
same story.)

---

## 3. 2G / GSM: one-way authentication

**The standard never asked the network to prove itself, and encryption was a network choice
rather than a floor.** Both facts are structural, not implementation bugs — the next two
generations spend their entire design budget undoing them.

### Authentication: A3/A8, one direction only

GSM authentication runs the **A3** (authentication) and **A8** (key generation) algorithms,
keyed by the subscriber key `Ki` (called `K` throughout this project), over a random challenge:

```
RAND (128-bit challenge, network → phone)
  --A3(Ki, RAND)-->  SRES  (32-bit signed response, phone → network)
  --A8(Ki, RAND)-->  Kc    (64-bit ciphering key, kept by both sides)
```

The network checks `SRES` against what it computed; if it matches, the phone is authenticated.
**Nothing in this exchange lets the phone check anything about the network.** There is no
network-side proof of key possession anywhere in the GSM protocol — no equivalent of 4G/5G's
`AUTN`. A base station that holds no key at all can simply skip straight past this step (or never
offer a challenge in the first place) and the phone has no way to notice.

A3/A8 were historically implemented as the (non-standardised, operator-chosen) **COMP128**
family of algorithms; 3GPP later published MILENAGE (TS 35.206) as the standard alternative used
by 3G/4G/5G AKA. This project does not implement COMP128. Instead, `ocr-gsm::auth_vector` derives
the 2G triplet by running MILENAGE and then applying the documented **3GPP TS 33.102 §6.8.1.2
UMTS→GSM interworking** conversion:

```
SRES = XRES[0..4] XOR XRES[4..8]
Kc   = CK[0..8] XOR CK[8..16] XOR IK[0..8] XOR IK[8..16]
```

This is a real, standards-defined conversion (used in practice whenever a UMTS/LTE-provisioned
SIM falls back to 2G), not an invented shortcut — it's simply a different, equally valid way to
reach a 2G triplet than raw COMP128, and it lets the 2G code reuse the same validated MILENAGE
core the other two generations use. `SQN`/`AMF` play no role in the GSM triplet (only `f1`/`f1*`
read them, and the triplet never uses those outputs), so the crate fixes both to zero for
reproducibility — see the `GSM_TRIPLET_SQN`/`GSM_TRIPLET_AMF` comments in `ocr-gsm` for the exact
reasoning.

### Ciphering: the network's unilateral choice

Once (if) authentication completes, the network commands a cipher with a **Cipher Mode
Command**, naming one of:

- **A5/1** — the original, still-widely-deployed stream cipher.
- **A5/3** (KASUMI-based) — the stronger, later option.
- **A5/0** — **no encryption at all.** Legal. The network's choice alone.

The phone has no mechanism to refuse a cipher — not even the null one — and there is **no
integrity protection on GSM signalling whatsoever**, so nothing stops a rogue network from simply
commanding `A5/0` regardless of what a real network there would have chosen.

### The consequence: the classic catcher

Put the two facts together and the entire classic IMSI-catcher recipe falls out for free:

1. Cell (re)selection follows signal strength (see `ocr-air`), so a base station that simply
   **out-shouts** the real network on the same PLMN gets phones to camp on it — no cryptography
   needed to win this step.
2. On a location update, a network that doesn't recognise the phone's TMSI (which a pure catcher
   never will, since it isn't the real network) sends an **Identity Request (IMSI)**, and the
   phone — with no way to have verified the network first — answers with its permanent identity
   in the clear. This happens *before* any authentication challenge, so a catcher that holds no
   keys at all doesn't even need to attempt AKA to get the prize.
3. If the catcher wants to relay real traffic rather than just harvest the identity and drop the
   phone, it commands `A5/0` and the phone complies unconditionally.
4. None of this requires defeating a single cryptographic primitive. The attack is entirely about
   the protocol never asking the right question.

**Standards:** 3GPP TS 43.020 (GSM security-related network functions — the A3/A8/A5 framework);
TS 33.102 §6.8.1.2 (UMTS↔GSM authentication interworking, the conversion this project implements);
TS 35.206 / TS 35.207 / TS 35.208 (MILENAGE algorithm specification and published test vectors).

---

## 4. 4G / LTE: EPS-AKA — mutual auth, and the gaps that survive it

EPS-AKA extends UMTS AKA (TS 33.102) into the EPS/LTE context per **TS 33.401**. The headline
change: the network now has to *prove* it holds the subscriber key, via `AUTN`.

### The vector and the proof

The HSS/AuC runs MILENAGE (`f1`–`f5`) over `RAND`, a sequence number `SQN`, and an authentication
management field `AMF`, and assembles:

```
AUTN = (SQN XOR AK) || AMF || MAC-A         (16 bytes)
XRES = RES                                   (8 bytes, kept by the network)
K_ASME = KDF(CK || IK, "FC=0x10 || SNid || SQN⊕AK")   (TS 33.401 Annex A.2)
```

`MAC-A` is a MAC over `SQN`/`AMF` computed under the subscriber's own key `K` (MILENAGE `f1`). A
network that does not hold `K` — a naive fake eNodeB — **cannot forge a valid `MAC-A`**, which is
exactly what closes the naive 2G-style "just ask" attack: the UE recomputes the same MAC under
its own key (`ue_verify_challenge` in `ocr-lte`) and rejects anything that doesn't match. This is
the mutual half of "mutual authentication" — the phone finally gets to authenticate the network,
not just the reverse.

Two distinguishable ways the UE can reject a challenge, both of which the range models as
genuinely different outcomes because the difference is itself meaningful:

- **MAC failure** — the recomputed MAC doesn't match the one in `AUTN`. The far side does not
  hold `K`. No `AUTS` is produced. Reported as `AuthenticationFailureMacFailure`.
- **Sync(hronisation) failure** — the MAC is fine (so the far side *does* hold `K` and this really
  is a genuine authentication vector for this subscriber), but the recovered `SQN` falls outside
  the UE's acceptance window (TS 33.102 Annex C.2; the range uses the standard 2²⁸ window,
  `UeSqnState::DEFAULT_WINDOW`). The UE replies with `AUTS = (SQN_MS XOR AK*) || MAC-S` so the
  network can resynchronise. Reported as `AuthenticationFailureSyncFailure`.

That these two failures look different on the air — "not your key" versus "your key, stale
counter" — is itself a side channel (§5 covers where it matters most). A legitimate, entirely
benign cause of sync failures exists: SQN state drifting when the same SIM is used across
multiple devices, which is common with dual-SIM adapters and SIM-swapping between phones.

### The gap: identity still leaks before any of this runs

Here's the catch that survives into 4G. On attach, if the network doesn't recognise the phone's
`GUTI` — a genuine first attach, a cleared MME record, or (the attack case) a fake eNodeB that was
never issued one and can't recognise anyone's — the network sends a plain **NAS Identity
Request**, and the UE answers with its **IMSI in the clear** (TS 24.301 EMM procedures). This
travels **before any NAS security context exists at all**: no cipher, no integrity, nothing. A
fake eNodeB that can never complete EPS-AKA (it holds no `K`, so every challenge it might attempt
fails the MAC check above) still walks away with the IMSI, because it never needed to run AKA in
the first place — it just needed to ask before security came up.

`pre_security_identity_exchange` in `ocr-lte` models this end to end, and `SecurityContext` makes
the exposure explicit: a context is only `is_protected()` once a *non-null* algorithm has been
established — establishing the null pair (`EEA0_EIA0`) still marks the context "established" but
leaves it unprotected, same as GSM's `A5/0`. The headline 2G attack is closed for anyone who
reaches a completed, non-null authentication; the identity that already crossed the air before
that point is not retroactively protected by anything that happens afterward.

### The other gap: unprotected pre-auth signalling enables bidding-down

**Attach Reject, Tracking Area Update Reject, and RRC Connection Reject all travel before
integrity protection exists**, so the phone has no way to verify one actually came from a
trustworthy source. A rogue eNodeB can reject an attach with a cause telling the phone LTE
service isn't available here, and the phone — behaving correctly per spec — falls back to
whatever RAT is left. If that's GSM, every Track 1 weakness is available again, undoing whatever
protection reaching LTE would have provided. This is the **LTEInspector / aLTEr** family of
findings: pre-authentication messages that are unauthenticated by design because nothing has been
negotiated yet to authenticate them with, used to force a bidding-down, deny service outright, or
harvest capability/measurement information the phone reports before security is up.

**Standards:** TS 33.401 (EPS security architecture; Annex A.2 for the `K_ASME` derivation); TS
24.301 (EPS NAS protocol — Identity Request/Response, Attach/TAU procedures and reject handling);
TS 33.102 (root UMTS AKA and the SQN acceptance window, Annex C.2); TS 35.206 (MILENAGE, still the
underlying algorithm); TS 33.220 (the generic HMAC-SHA-256 KDF that `K_ASME` reuses).

**Research:** Hussain, Chowdhury, Mehnaz, Bertino, *LTEInspector: A Systematic Approach for
Adversarial Testing of 4G LTE* (NDSS 2018) — systematic pre-auth/bidding-down weaknesses found via
model checking; Rupprecht, Kohls, Holz, Pöpper, *Breaking LTE on Layer Two* (IEEE S&P 2019) — the
aLTEr attack, exploiting unprotected/unencrypted-integrity layer-two signalling; Hussain,
Echeverria, Chowdhury, Li, Bertino, *Privacy Attacks to the 4G and 5G Cellular Paging Protocols
Using Side Channel Information* (NDSS 2019) — introduces **ToRPEDO** and **PIERCER**, paging-based
presence-confirmation and identity-mapping side channels that exploit IMSI-paging and predictable
paging occasions.

---

## 5. 5G / NR: 5G-AKA and SUCI — the fix, and its remaining seams

5G's answer to the 4G gap is not a patch to EPS-AKA's flow — it's removing the plaintext identity
that flow depended on leaking. SUCI concealment (§1.4) means there is, for the first time, no
useful cleartext permanent identity for a pre-auth message to request.

### 5G-AKA: EPS-AKA's key hierarchy, extended

5G-AKA builds the vector the same way EPS-AKA does — the same MILENAGE core, the same `AUTN`
structure — but changes what comes out of it (**TS 33.501**, primarily §6.1.3.2 and Annex A):

```
AUTN = (SQN XOR AK) || AMF || MAC-A                                   (unchanged shape)
RES*/XRES* = HMAC-SHA-256(CK || IK, FC=0x6B || SNN || RAND || RES)[least-significant 128 bits]
K_AUSF     = HMAC-SHA-256(CK || IK, FC=0x6A || SNN || SQN⊕AK)
K_SEAF     = HMAC-SHA-256(K_AUSF,   FC=0x6C || SNN)
```

(All via the same TS 33.220 generic HMAC-SHA-256 KDF the 4G key hierarchy uses — 5G doesn't
introduce a new primitive, it composes the existing one further.) Two changes worth calling out:

- **`RES*`/`XRES*` bind in the serving network name** (`SNN`, formatted per TS 33.501 §6.1.1.4 as
  `"5G:mnc<MNC>.mcc<MCC>.3gppnetwork.org"`). A vector computed for one serving network can't be
  silently reused to authenticate against a different one.
- **The comparison of `RES*`/`XRES*` is designed to let the serving network's SEAF prove to the
  subscriber's home-network AUSF that authentication actually succeeded** — closing a
  roaming-trust gap in EPS-AKA where a visited network could complete authentication without ever
  proving it to the home network. That AUSF/SEAF confirmation round trip is a core-network-internal
  step, not something that crosses the radio air, so it's noted here for completeness rather than
  modelled as its own message in this project.

The two authentication-failure outcomes are structurally identical to 4G's — a `MacFailure` (no
`AUTS`) versus a `SynchFailure` (with `AUTS`) — because they're the same underlying MILENAGE
mechanism (`AuthFailureCause` in `ocr-nr` mirrors `UeAuthOutcome` in `ocr-lte` exactly). What's
different about 5G is *why this distinguishability now matters more* (see below).

### The fix: no more plaintext identity request

In 5G NAS, the network's identity-request message asks for a **SUCI**, not a bare SUPI
(`IdentityRequestSuci` / `IdentityResponseSuci` in `ocr-nr`). Run the identical rogue-cell attack
shape that catches an IMSI on 2G and 4G — stronger signal, reselection, identity request — and
under a real protection scheme the response is ciphertext a keyless attacker cannot open. The
pre-auth cleartext-identity lever that powered every earlier chapter's headline attack is
structurally gone, not merely disabled by policy.

### But the fix is optional, and the seams around it are the point

- **Null-scheme SUCI (Protection Scheme 0) is spec-legal.** A "SUCI" concealed under the null
  scheme carries the SUPI in the clear inside a SUCI-shaped message. Nothing about the wire format
  distinguishes "properly concealed" from "null-scheme" except the scheme field itself — a
  network or subscriber profile left in this mode is fully standards-compliant and fully exposed.
- **Downgrade is still possible.** A 5G cell's own broadcast can permit fallback to LTE (or
  beyond); the range models this directly as `NrRrcMessage::SystemInformation.allows_downgrade`.
  When it's allowed, every earlier chapter's weaknesses are reachable again exactly as in the 4G
  downgrade case.
- **The AKA failure-message linkability oracle.** This is where the MAC-failure/sync-failure
  distinguishability described above stops being an implementation curiosity and becomes the
  headline remaining leak: once the *identity itself* is finally concealed, replaying a
  previously-observed `AUTN` and watching which failure comes back is one of the few things left
  that can link a sighting to a specific subscriber. A `MacFailure` says "not this SIM's key"; a
  `SynchFailure` says "this really is the subscriber's key, the counter is just stale" —
  confirming presence without ever learning the SUPI. Concealing the identity does not close this;
  the failure message itself is the oracle. This (and the closely related SUCI/`AUTS` replay
  linkability) is exactly what the formal-verification and privacy literature below identified,
  and it's why 3GPP later added mitigation guidance to later releases — it is a known,
  documented, still-live seam, not a hypothetical.
- **5G-GUTI reallocation cadence.** A "temporary" identifier that's reallocated too infrequently
  is durable enough to track like a pseudo-permanent id, even without ever touching the SUPI.
- **Traffic analysis survives concealment.** Paging and connection-timing patterns still reveal
  *when* a known subscriber is present, independent of whether their identity was ever readable —
  a structural limit of a radio medium, not a protocol bug. (The parallel this project's sibling
  draws explicitly: this is cellular's version of OSDP's plaintext command byte still leaking
  device-open/device-closed timing after OSDP fixed Wiegand's plaintext card data.)

**Standards:** TS 33.501 (5G security architecture — §6.1.3.2 for 5G-AKA, Annex A for the key
derivations above, Annex C for SUCI protection schemes and the Annex C.4 worked example); TS
24.501 (5G NAS protocol — registration and identity procedures); TS 33.220 (the generic KDF, again
reused); TS 35.206 (MILENAGE, still the base algorithm three generations deep).

**Research:** Basin, Dreier, Hirschi, Radomirović, Sasse, Stettler, *A Formal Analysis of 5G
Authentication* (ACM CCS 2018) — the formal-methods analysis that surfaced the sequence-number/
linkability weaknesses in 5G-AKA as specified; Borgaonkar, Hirschi, Park, Shaik, *New Privacy
Threat on 3G, 4G, and Upcoming 5G AKA Protocols* (Proceedings on Privacy Enhancing Technologies,
2019) — the AKA failure-message linkability attack specifically, showing it applies across 3G, 4G
and 5G's shared AKA lineage; Hussain, Echeverria, Chowdhury, Li, Bertino, *Privacy Attacks to the
4G and 5G Cellular Paging Protocols Using Side Channel Information* (NDSS 2019) — ToRPEDO/PIERCER,
which apply to 5G paging as much as 4G's.

---

## 6. Where to verify this in the code

Every numeric claim above is backed by a test, not just a comment:

- MILENAGE `f1`–`f5`, `f1*`, `f5*` against 3GPP TS 35.208 test sets 1, 3, 4, 5 —
  `crates/ocr-crypto/src/lib.rs`.
- The GSM 2G-triplet interworking conversion (`SRES`/`Kc`) against the same TS 35.208 vector —
  `crates/ocr-gsm/src/lib.rs`.
- `K_ASME`'s exact KDF input string and HMAC-SHA-256 computation, independently re-derived in the
  test rather than just calling the same helper — `crates/ocr-lte/src/lib.rs`.
- `RES*`/`XRES*` agreement between network and UE, and `K_SEAF` determinism —
  `crates/ocr-nr/src/lib.rs`.
- SUCI Profile A against the **published TS 33.501 Annex C.4 numeric example** (fixed home key
  pair, ephemeral key, ciphertext, and MAC that must decrypt to a known MSIN) —
  `crates/ocr-crypto/src/lib.rs`'s `suci` module.

If you're teaching from this document, those tests are the place to point someone who asks "how
do you know this is right" — they check against publicly published numbers, not just internal
consistency.
