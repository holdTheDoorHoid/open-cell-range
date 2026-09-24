// engine-mock.js — a JavaScript reference implementation of the contract in
// site/ENGINE-API.md. Canned but honest: the data here is what a correct engine
// would produce for these drills. It exists so the site can be built and
// deployed without a Rust/wasm toolchain, and as the readable statement of the
// contract. The real engine is engine-wasm.js.
//
// Every scenario is modelled as two frames: phase 0 is the initial world
// (nothing has happened yet, one flag waiting), phase 1 is the world after the
// scenario's headline attacker runs. That mirrors DESIGN.md section 2: each
// drill runs one real attack against one real (simulated) air, and a flag is
// only "captured" because engine state reached it — never because a UI label
// changed. The defend drill is the deliberate exception: its "attack" already
// happened before the learner arrived, so phase 0 already carries the full air
// log and only the monitor's findings are missing — running it means running
// the passive monitor, not causing anything new to happen on the air.
//
// Frozen shape (do not add or rename fields): see site/ENGINE-API.md.
// `now_us` is derived from the frame's own events so it never needs hand
// synchronising with the log: 0 for a quiet world, or a little past the last
// message once something has happened.
//
// A recurring "tell" is deliberate: every rogue cell in this file broadcasts
// the maximum-value area code for its RAT — 65535 (0xFFFF) for GSM/LTE's
// 16-bit LAC/TAC, 16777215 (0xFFFFFF) for NR's 24-bit TAC. Real networks never
// assign the reserved/placeholder maximum to a live cell, so a monitor calling
// that out is a realistic, concrete finding — and a learner who notices the
// same number reappear across a scenario (see lte-4g-downgrade) is reading the
// same correlation a real analyst would.

const CATALOG = [
  { slug: 'gsm-2g-imsi-catch', title: 'Catch an IMSI on 2G', track: '2g',
    brief: 'Stand up a rogue cell that out-signals the network and ask the phone who it is. In 2G it just answers.' },
  { slug: 'gsm-2g-null-cipher', title: 'Turn off encryption', track: '2g',
    brief: 'The network picks the cipher. A rogue cell picks A5/0 — none.' },
  { slug: 'lte-4g-imsi-catch', title: 'Catch an IMSI on LTE', track: '4g',
    brief: 'Mutual auth stops a fake tower serving traffic, but the IMSI still leaks before security starts.' },
  { slug: 'lte-4g-downgrade', title: 'Force a downgrade to 2G', track: '4g',
    brief: 'An unprotected reject pushes the phone off LTE and down to GSM, where the 2G attacks apply.' },
  { slug: 'nr-5g-suci-protects', title: 'SUCI does its job', track: '5g',
    brief: 'Ask a 5G phone for its identity. It answers with a SUCI you cannot read. The fix, working.' },
  { slug: 'nr-5g-null-scheme', title: 'Undo SUCI with the null scheme', track: '5g',
    brief: 'A network configured for the null protection scheme sends the SUPI in the clear anyway.' },
  { slug: 'defend-spot-the-catcher', title: 'Spot the catcher', track: 'defend',
    brief: 'Run the passive monitor over an already-attacked world and raise the finding a real detector would.' },
];

// Honest canned snapshots keyed by slug: [phase0 (initial), phase1 (post-attack)].
const SNAPSHOTS = {

  // ---------------------------------------------------------------------
  // Track 1 — 2G / GSM: one-way auth, optional cipher chosen by the network.
  // ---------------------------------------------------------------------

  'gsm-2g-imsi-catch': [
    { cells: [
        { id: 1, rat: 'gsm', plmn: '310-260', signal_dbm: -70, area_code: 4102 } ],
      ue: { camped_on: 1, camped_rat: 'gsm', imsi_leaked: false, null_cipher_active: false },
      events: [], findings: [],
      flags: [ { id: 'imsi-in-hand', title: 'Recover the IMSI', captured: false,
                 hint: 'A 2G phone answers an Identity Request before it trusts the cell. First get it to camp on you.' } ] },
    { cells: [
        { id: 1, rat: 'gsm', plmn: '310-260', signal_dbm: -70, area_code: 4102 },
        { id: 7, rat: 'gsm', plmn: '310-260', signal_dbm: -45, area_code: 65535 } ],
      ue: { camped_on: 7, camped_rat: 'gsm', imsi_leaked: true, null_cipher_active: false },
      events: [
        { t_us: 60000, rat: 'gsm', cell: 1, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'The home cell broadcasts normal system information.' },
        { t_us: 200000, rat: 'gsm', cell: 7, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'A second cell appears, announcing the same network id with a much stronger signal.' },
        { t_us: 240000, rat: 'gsm', cell: 7, dir: 'observed', msg: 'CellReselection',
          summary: 'The phone reselects onto the stronger cell — ordinary behaviour; nothing about the network id looked wrong.' },
        { t_us: 320000, rat: 'gsm', cell: 7, dir: 'net_to_ue', msg: 'IdentityRequest(IMSI)',
          summary: 'The rogue cell asks the phone for its IMSI.' },
        { t_us: 360000, rat: 'gsm', cell: 7, dir: 'ue_to_net', msg: 'IdentityResponse(IMSI)',
          summary: 'The phone answers with its IMSI in the clear — 2G never asks the network to prove itself first.' } ],
      findings: [
        { kind: 'CleartextIdentityRequest', severity: 'High', t_us: 320000,
          detail: 'A cell requested the permanent identity in the clear before any authentication took place.' },
        { kind: 'UnexpectedAreaCode', severity: 'Medium', t_us: 200000,
          detail: 'Cell 7 broadcasts area code 65535 (0xFFFF) — the reserved maximum, never assigned on a live GSM network.' } ],
      flags: [ { id: 'imsi-in-hand', title: 'Recover the IMSI', captured: true,
                 hint: 'A 2G phone answers an Identity Request before it trusts the cell.' } ] },
  ],

  'gsm-2g-null-cipher': [
    { cells: [
        { id: 2, rat: 'gsm', plmn: '310-260', signal_dbm: -75, area_code: 4102 } ],
      ue: { camped_on: 2, camped_rat: 'gsm', imsi_leaked: false, null_cipher_active: false },
      events: [], findings: [],
      flags: [ { id: 'null-cipher-forced', title: 'Force A5/0 (no encryption)', captured: false,
                 hint: 'The network chooses the cipher mode, not the phone — it cannot refuse. Get the phone talking to your cell, then command A5/0.' } ] },
    { cells: [
        { id: 2, rat: 'gsm', plmn: '310-260', signal_dbm: -75, area_code: 4102 },
        { id: 8, rat: 'gsm', plmn: '310-260', signal_dbm: -42, area_code: 65535 } ],
      ue: { camped_on: 8, camped_rat: 'gsm', imsi_leaked: true, null_cipher_active: true },
      events: [
        { t_us: 50000, rat: 'gsm', cell: 2, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'The home cell broadcasts normal system information.' },
        { t_us: 190000, rat: 'gsm', cell: 8, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'A rogue cell broadcasts the same network id with a much stronger signal.' },
        { t_us: 230000, rat: 'gsm', cell: 8, dir: 'observed', msg: 'CellReselection',
          summary: 'The phone reselects onto the stronger cell.' },
        { t_us: 300000, rat: 'gsm', cell: 8, dir: 'net_to_ue', msg: 'IdentityRequest(IMSI)',
          summary: 'The rogue cell asks for the IMSI first, as usual.' },
        { t_us: 330000, rat: 'gsm', cell: 8, dir: 'ue_to_net', msg: 'IdentityResponse(IMSI)',
          summary: 'The phone answers in the clear.' },
        { t_us: 380000, rat: 'gsm', cell: 8, dir: 'net_to_ue', msg: 'CipherModeCommand(A5/0)',
          summary: 'The rogue network commands A5/0 — the null cipher. The phone has no way to refuse a cipher the network picks.' },
        { t_us: 410000, rat: 'gsm', cell: 8, dir: 'ue_to_net', msg: 'CipherModeComplete',
          summary: 'The phone confirms. Every signalling and voice frame on this cell is now unencrypted.' } ],
      findings: [
        { kind: 'CleartextIdentityRequest', severity: 'High', t_us: 300000,
          detail: 'A cell requested the permanent identity in the clear before any authentication took place.' },
        { kind: 'ForcedNullCipher', severity: 'High', t_us: 380000,
          detail: 'The network commanded A5/0. All further voice, SMS, and signalling to this phone are unencrypted and readable to anyone nearby.' } ],
      flags: [ { id: 'null-cipher-forced', title: 'Force A5/0 (no encryption)', captured: true,
                 hint: 'The network chooses the cipher mode, not the phone.' } ] },
  ],

  // ---------------------------------------------------------------------
  // Track 2 — 4G / LTE: mutual auth closes the headline hole, but not the
  // pre-security messages.
  // ---------------------------------------------------------------------

  'lte-4g-imsi-catch': [
    { cells: [
        { id: 3, rat: 'lte', plmn: '310-260', signal_dbm: -80, area_code: 20401 } ],
      ue: { camped_on: 3, camped_rat: 'lte', imsi_leaked: false, null_cipher_active: false },
      events: [], findings: [],
      flags: [ { id: 'imsi-in-hand', title: 'Recover the IMSI before security starts', captured: false,
                 hint: 'A fake eNodeB can’t finish mutual authentication — but the network still asks for the IMSI in cleartext before it even tries that. Get the phone attaching to you first.' } ] },
    { cells: [
        { id: 3, rat: 'lte', plmn: '310-260', signal_dbm: -80, area_code: 20401 },
        { id: 13, rat: 'lte', plmn: '310-260', signal_dbm: -40, area_code: 65535 } ],
      ue: { camped_on: 13, camped_rat: 'lte', imsi_leaked: true, null_cipher_active: false },
      events: [
        { t_us: 50000, rat: 'lte', cell: 3, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'The home eNodeB broadcasts normal system information (MIB/SIB1).' },
        { t_us: 170000, rat: 'lte', cell: 13, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'A rogue eNodeB broadcasts the same PLMN with a much stronger signal.' },
        { t_us: 210000, rat: 'lte', cell: 13, dir: 'observed', msg: 'CellReselection',
          summary: 'The phone reselects onto the stronger cell — the network identity looks the same, so nothing warns it off.' },
        { t_us: 260000, rat: 'lte', cell: 13, dir: 'ue_to_net', msg: 'AttachRequest(GUTI)',
          summary: 'The phone attaches using its temporary identity (GUTI), trying to avoid ever sending the IMSI over the air.' },
        { t_us: 290000, rat: 'lte', cell: 13, dir: 'net_to_ue', msg: 'IdentityRequest(IMSI)',
          summary: 'The rogue network claims not to recognise the GUTI and asks for the permanent identity instead. This message travels before any security context exists, so nothing on the phone can verify or refuse it.' },
        { t_us: 320000, rat: 'lte', cell: 13, dir: 'ue_to_net', msg: 'IdentityResponse(IMSI)',
          summary: 'The phone answers with its IMSI in the clear. Mutual authentication never even started.' } ],
      findings: [
        { kind: 'CleartextIdentityRequest', severity: 'High', t_us: 290000,
          detail: 'A cell requested the permanent identity (IMSI) before any security context existed — this still works even though LTE authentication is mutual, because the request happens first.' },
        { kind: 'UnexpectedAreaCode', severity: 'Medium', t_us: 170000,
          detail: 'Cell 13 broadcasts tracking area code 65535 (0xFFFF) — the reserved maximum, never assigned on a live LTE network.' } ],
      flags: [ { id: 'imsi-in-hand', title: 'Recover the IMSI before security starts', captured: true,
                 hint: 'A fake eNodeB can’t finish mutual authentication, but the pre-security Identity Request still works.' } ] },
  ],

  'lte-4g-downgrade': [
    { cells: [
        { id: 4, rat: 'lte', plmn: '310-260', signal_dbm: -75, area_code: 20401 } ],
      ue: { camped_on: 4, camped_rat: 'lte', imsi_leaked: false, null_cipher_active: false },
      events: [], findings: [],
      flags: [ { id: 'downgrade-forced', title: 'Force a fallback to 2G', captured: false,
                 hint: 'LTE reject messages travel before integrity protection exists, so the phone can’t tell a forged one from a real one. Push the phone off LTE and watch where it lands.' } ] },
    { cells: [
        { id: 4, rat: 'lte', plmn: '310-260', signal_dbm: -75, area_code: 20401 },
        { id: 14, rat: 'lte', plmn: '310-260', signal_dbm: -41, area_code: 65535 },
        { id: 24, rat: 'gsm', plmn: '310-260', signal_dbm: -43, area_code: 65535 } ],
      ue: { camped_on: 24, camped_rat: 'gsm', imsi_leaked: true, null_cipher_active: false },
      events: [
        { t_us: 50000, rat: 'lte', cell: 4, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'The home eNodeB broadcasts normal system information.' },
        { t_us: 160000, rat: 'lte', cell: 14, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'A rogue eNodeB broadcasts the same PLMN with a much stronger signal.' },
        { t_us: 200000, rat: 'lte', cell: 14, dir: 'observed', msg: 'CellReselection',
          summary: 'The phone reselects onto the stronger cell.' },
        { t_us: 240000, rat: 'lte', cell: 14, dir: 'ue_to_net', msg: 'AttachRequest(GUTI)',
          summary: 'The phone attempts to attach.' },
        { t_us: 270000, rat: 'lte', cell: 14, dir: 'net_to_ue', msg: 'AttachReject(#7 EPS-services-not-allowed)',
          summary: 'The rogue network rejects the attach with a cause code that tells the phone not to try LTE here. This message has no integrity protection — nothing on the phone can verify it actually came from a trustworthy source.' },
        { t_us: 300000, rat: 'lte', cell: 14, dir: 'observed', msg: 'RatBarred',
          summary: 'The phone disables LTE for this PLMN and reselects to GSM, exactly as the reject instructed.' },
        { t_us: 330000, rat: 'gsm', cell: 24, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'The same attacker’s rogue GSM cell is waiting where the phone was steered.' },
        { t_us: 360000, rat: 'gsm', cell: 24, dir: 'net_to_ue', msg: 'IdentityRequest(IMSI)',
          summary: 'Now on 2G, the rogue cell asks for the IMSI — the one-way-auth attack from Track 1 applies again.' },
        { t_us: 390000, rat: 'gsm', cell: 24, dir: 'ue_to_net', msg: 'IdentityResponse(IMSI)',
          summary: 'The phone answers in the clear. The downgrade paid off.' } ],
      findings: [
        { kind: 'UnprotectedRejectMessage', severity: 'High', t_us: 270000,
          detail: 'An Attach Reject arrived before any integrity protection was established, and it changed the phone’s future cell selection — a classic bidding-down primitive.' },
        { kind: 'ForcedRatDowngrade', severity: 'High', t_us: 300000,
          detail: 'The phone was steered off a mutually-authenticated RAT and onto GSM, where authentication is one-way and encryption is optional.' },
        { kind: 'CleartextIdentityRequest', severity: 'High', t_us: 360000,
          detail: 'Once on GSM, the permanent identity was requested and handed over in the clear — the payoff of the downgrade.' },
        { kind: 'UnexpectedAreaCode', severity: 'Medium', t_us: 160000,
          detail: 'Both cell 14 (LTE) and cell 24 (GSM) broadcast area code 65535 (0xFFFF) — the same reserved placeholder value on two different radios is strong evidence they are the same rogue infrastructure.' } ],
      flags: [ { id: 'downgrade-forced', title: 'Force a fallback to 2G', captured: true,
                 hint: 'LTE reject messages travel before integrity protection exists.' } ] },
  ],

  // ---------------------------------------------------------------------
  // Track 3 — 5G / NR: SUCI is the fix — when it isn't configured away.
  // ---------------------------------------------------------------------

  'nr-5g-suci-protects': [
    { cells: [
        { id: 5, rat: 'nr', plmn: '310-260', signal_dbm: -85, area_code: 41102 } ],
      ue: { camped_on: 5, camped_rat: 'nr', imsi_leaked: false, null_cipher_active: false },
      events: [], findings: [],
      flags: [ { id: 'suci-holds', title: 'Confirm SUCI holds even under attack', captured: false,
                 hint: 'Stand up a rogue cell exactly as you would for the 2G or 4G drills and ask for the identity — then see what comes back.' } ] },
    { cells: [
        { id: 5, rat: 'nr', plmn: '310-260', signal_dbm: -85, area_code: 41102 },
        { id: 15, rat: 'nr', plmn: '310-260', signal_dbm: -38, area_code: 16777215 } ],
      ue: { camped_on: 15, camped_rat: 'nr', imsi_leaked: false, null_cipher_active: false },
      events: [
        { t_us: 50000, rat: 'nr', cell: 5, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'The home gNodeB broadcasts normal system information.' },
        { t_us: 170000, rat: 'nr', cell: 15, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'A rogue gNodeB broadcasts the same PLMN with a much stronger signal.' },
        { t_us: 210000, rat: 'nr', cell: 15, dir: 'observed', msg: 'CellReselection',
          summary: 'The phone reselects onto the stronger cell — same as every generation before it.' },
        { t_us: 260000, rat: 'nr', cell: 15, dir: 'net_to_ue', msg: 'IdentityRequest(SUCI)',
          summary: 'The rogue network asks the phone for its subscription identifier.' },
        { t_us: 300000, rat: 'nr', cell: 15, dir: 'ue_to_net', msg: 'IdentityResponse(SUCI)',
          summary: 'The phone answers — but with a SUCI: the SUPI encrypted under the home network’s public key (ECIES Profile A). The rogue network has no home-network private key, so this is unreadable ciphertext to it. Compare this to the 2G and 4G drills: the request looks the same, the answer does not.' } ],
      findings: [
        { kind: 'SuspiciousCellPresent', severity: 'Low', t_us: 170000,
          detail: 'A new cell broadcasting the same network id appeared with an implausibly strong signal, and area code 16777215 (0xFFFFFF) — the reserved 24-bit maximum. Worth watching, but on its own it is not proof of a successful identity attack.' },
        { kind: 'ConcealedIdentityResponse', severity: 'Info', t_us: 300000,
          detail: 'The phone concealed its permanent identity with SUCI. A passive or rogue listener recovers only ciphertext here — no IMSI/SUPI equivalent.' } ],
      flags: [ { id: 'suci-holds', title: 'Confirm SUCI holds even under attack', captured: true,
                 hint: 'The attacker still stood up a rogue cell and asked for the identity — this flag captures that the answer was unreadable. The fix worked.' } ] },
  ],

  'nr-5g-null-scheme': [
    { cells: [
        { id: 6, rat: 'nr', plmn: '310-260', signal_dbm: -82, area_code: 41102 } ],
      ue: { camped_on: 6, camped_rat: 'nr', imsi_leaked: false, null_cipher_active: false },
      events: [], findings: [],
      flags: [ { id: 'supi-in-hand', title: 'Recover the SUPI despite SUCI', captured: false,
                 hint: 'SUCI only protects the identity if the protection scheme is non-null. Find a profile still configured for Protection Scheme 0 and ask for the identity.' } ] },
    { cells: [
        { id: 6, rat: 'nr', plmn: '310-260', signal_dbm: -82, area_code: 41102 },
        { id: 16, rat: 'nr', plmn: '310-260', signal_dbm: -39, area_code: 16777215 } ],
      ue: { camped_on: 16, camped_rat: 'nr', imsi_leaked: true, null_cipher_active: false },
      events: [
        { t_us: 50000, rat: 'nr', cell: 6, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'The home gNodeB broadcasts normal system information.' },
        { t_us: 170000, rat: 'nr', cell: 16, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'A rogue gNodeB broadcasts the same PLMN with a much stronger signal.' },
        { t_us: 210000, rat: 'nr', cell: 16, dir: 'observed', msg: 'CellReselection',
          summary: 'The phone reselects onto the stronger cell.' },
        { t_us: 260000, rat: 'nr', cell: 16, dir: 'net_to_ue', msg: 'IdentityRequest(SUCI)',
          summary: 'The rogue network asks for the subscription identifier.' },
        { t_us: 300000, rat: 'nr', cell: 16, dir: 'ue_to_net', msg: 'IdentityResponse(SUCI, scheme=null)',
          summary: 'The phone answers with a SUCI — but this subscriber profile is configured for Protection Scheme 0, the null scheme. The "concealed" identifier is just the SUPI with no encryption applied at all.' } ],
      findings: [
        { kind: 'NullProtectionSchemeSuci', severity: 'High', t_us: 300000,
          detail: 'The SUCI carried Protection Scheme 0 (null). The permanent identifier (SUPI) is readable in the clear despite the concealment mechanism being present in the message. This is a legal, spec-permitted configuration — and it defeats the entire point of SUCI.' },
        { kind: 'UnexpectedAreaCode', severity: 'Medium', t_us: 170000,
          detail: 'Cell 16 broadcasts area code 16777215 (0xFFFFFF) — the reserved 24-bit maximum, never assigned on a live NR network.' } ],
      flags: [ { id: 'supi-in-hand', title: 'Recover the SUPI despite SUCI', captured: true,
                 hint: 'SUCI only protects the identity if the protection scheme is non-null.' } ] },
  ],

  // ---------------------------------------------------------------------
  // Defend track — same air, the monitor's side of the story.
  // ---------------------------------------------------------------------

  'defend-spot-the-catcher': [
    { cells: [
        { id: 9, rat: 'lte', plmn: '310-260', signal_dbm: -78, area_code: 20401 },
        { id: 19, rat: 'lte', plmn: '310-260', signal_dbm: -41, area_code: 65535 } ],
      ue: { camped_on: 19, camped_rat: 'lte', imsi_leaked: true, null_cipher_active: false },
      events: [
        { t_us: 50000, rat: 'lte', cell: 9, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'The home eNodeB broadcasts normal system information.' },
        { t_us: 170000, rat: 'lte', cell: 19, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'A second cell appears on the same PLMN with a much stronger signal.' },
        { t_us: 210000, rat: 'lte', cell: 19, dir: 'observed', msg: 'CellReselection',
          summary: 'The phone reselects onto the stronger cell.' },
        { t_us: 260000, rat: 'lte', cell: 19, dir: 'ue_to_net', msg: 'AttachRequest(GUTI)',
          summary: 'The phone attaches with its temporary identity.' },
        { t_us: 290000, rat: 'lte', cell: 19, dir: 'net_to_ue', msg: 'IdentityRequest(IMSI)',
          summary: 'The cell asks for the permanent identity before any security context exists.' },
        { t_us: 320000, rat: 'lte', cell: 19, dir: 'ue_to_net', msg: 'IdentityResponse(IMSI)',
          summary: 'The phone answers with its IMSI in the clear.' } ],
      findings: [],
      flags: [ { id: 'catcher-flagged', title: 'Raise the finding a real detector would', captured: false,
                 hint: 'The attack already happened before you arrived — that is the point of this drill. Read the air log, then run the passive monitor over it.' } ] },
    { cells: [
        { id: 9, rat: 'lte', plmn: '310-260', signal_dbm: -78, area_code: 20401 },
        { id: 19, rat: 'lte', plmn: '310-260', signal_dbm: -41, area_code: 65535 } ],
      ue: { camped_on: 19, camped_rat: 'lte', imsi_leaked: true, null_cipher_active: false },
      events: [
        { t_us: 50000, rat: 'lte', cell: 9, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'The home eNodeB broadcasts normal system information.' },
        { t_us: 170000, rat: 'lte', cell: 19, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'A second cell appears on the same PLMN with a much stronger signal.' },
        { t_us: 210000, rat: 'lte', cell: 19, dir: 'observed', msg: 'CellReselection',
          summary: 'The phone reselects onto the stronger cell.' },
        { t_us: 260000, rat: 'lte', cell: 19, dir: 'ue_to_net', msg: 'AttachRequest(GUTI)',
          summary: 'The phone attaches with its temporary identity.' },
        { t_us: 290000, rat: 'lte', cell: 19, dir: 'net_to_ue', msg: 'IdentityRequest(IMSI)',
          summary: 'The cell asks for the permanent identity before any security context exists.' },
        { t_us: 320000, rat: 'lte', cell: 19, dir: 'ue_to_net', msg: 'IdentityResponse(IMSI)',
          summary: 'The phone answers with its IMSI in the clear.' } ],
      findings: [
        { kind: 'CleartextIdentityRequest', severity: 'High', t_us: 290000,
          detail: 'A cell requested the permanent identity in the clear before any security context existed.' },
        { kind: 'UnexpectedAreaCode', severity: 'Medium', t_us: 170000,
          detail: 'Cell 19 broadcasts tracking area code 65535 (0xFFFF) — the reserved maximum, never assigned on a live network.' },
        { kind: 'ImplausibleSignalStrength', severity: 'Low', t_us: 170000,
          detail: '-41 dBm is stronger than a macro cell typically achieves outdoors — consistent with a small device very close to the phone.' } ],
      flags: [ { id: 'catcher-flagged', title: 'Raise the finding a real detector would', captured: true,
                 hint: 'The passive monitor concluded this from the air log alone, the same way a real detector would.' } ] },
  ],
};

// A fallback for any scenario slug not (yet) given canned data above: an
// empty-but-valid world, so the UI never breaks even if the catalogue grows
// ahead of this file.
function placeholder() {
  return [{ cells: [], ue: { camped_on: null, camped_rat: null, imsi_leaked: false, null_cipher_active: false },
            events: [], findings: [],
            flags: [ { id: 'todo', title: 'Coming soon', captured: false,
                       hint: 'This drill is being built. The reference engine has no canned data for it yet.' } ] }];
}

function nowFor(frame) {
  if (!frame.events.length) return 0;
  return frame.events[frame.events.length - 1].t_us + 20000;
}

export function createEngine() {
  let version = 0;
  let slug = null;
  let phase = 0;

  function snapshot() {
    const frames = SNAPSHOTS[slug] || placeholder();
    const frame = frames[Math.min(phase, frames.length - 1)];
    return {
      version,
      scenario: slug,
      now_us: nowFor(frame),
      cells: frame.cells,
      ue: frame.ue,
      events: frame.events,
      findings: frame.findings,
      flags: frame.flags,
    };
  }

  return {
    listScenarios() { return CATALOG.slice(); },
    load(s) { slug = s; phase = 0; version++; return snapshot(); },
    runAttack(_id) { phase = 1; version++; return snapshot(); },
    step(_dtUs) { version++; return snapshot(); },
    reset() { phase = 0; version++; return snapshot(); },
    state() { return snapshot(); },
  };
}
