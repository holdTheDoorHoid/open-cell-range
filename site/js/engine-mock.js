// engine-mock.js — a JavaScript reference implementation of the contract in
// site/ENGINE-API.md. Canned but honest: the data here is what a correct engine
// would produce for these drills. It exists so the site can be built and
// deployed without a Rust/wasm toolchain, and as the readable statement of the
// contract. The real engine is engine-wasm.js.
//
// This is a starting seam. The site agent expands the catalogue and the fidelity
// of the snapshots; the shapes must stay identical to ENGINE-API.md.

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
    brief: 'Run the passive monitor over an attacked world and raise the finding a real detector would.' },
];

// Honest canned snapshots keyed by (slug, phase). Phase 0 is the initial world;
// phase 1 is after the scenario's headline attacker runs.
const SNAPSHOTS = {
  'gsm-2g-imsi-catch': [
    { cells: [
        { id: 1, rat: 'gsm', plmn: '310-260', signal_dbm: -70, area_code: 4102 } ],
      ue: { camped_on: 1, camped_rat: 'gsm', imsi_leaked: false, null_cipher_active: false },
      events: [], findings: [],
      flags: [ { id: 'imsi-in-hand', title: 'Recover the IMSI', captured: false,
                 hint: 'A 2G phone answers an Identity Request before it trusts the cell. First get it to camp on you.' } ] },
    { cells: [
        { id: 1, rat: 'gsm', plmn: '310-260', signal_dbm: -70, area_code: 4102 },
        { id: 7, rat: 'gsm', plmn: '310-260', signal_dbm: -45, area_code: 9999 } ],
      ue: { camped_on: 7, camped_rat: 'gsm', imsi_leaked: true, null_cipher_active: false },
      events: [
        { t_us: 200000, rat: 'gsm', cell: 7, dir: 'net_to_ue', msg: 'SystemInformation',
          summary: 'Rogue cell broadcasts the target network with a strong signal' },
        { t_us: 320000, rat: 'gsm', cell: 7, dir: 'net_to_ue', msg: 'IdentityRequest(IMSI)',
          summary: 'Rogue cell asks the phone for its IMSI' },
        { t_us: 360000, rat: 'gsm', cell: 7, dir: 'ue_to_net', msg: 'IdentityResponse(IMSI)',
          summary: 'Phone answers with its IMSI in the clear' } ],
      findings: [
        { kind: 'CleartextIdentityRequest', severity: 'High', t_us: 320000,
          detail: 'A cell requested the permanent identity in the clear before any authentication.' } ],
      flags: [ { id: 'imsi-in-hand', title: 'Recover the IMSI', captured: true,
                 hint: 'A 2G phone answers an Identity Request before it trusts the cell.' } ] },
  ],
};

// A fallback for scenarios not yet given full canned data: an empty-but-valid world.
function placeholder(slug) {
  return [{ cells: [], ue: { camped_on: null, camped_rat: null, imsi_leaked: false, null_cipher_active: false },
            events: [], findings: [],
            flags: [ { id: 'todo', title: 'Coming soon', captured: false,
                       hint: 'This drill is being built. The reference engine has no canned data for it yet.' } ] }];
}

export function createEngine() {
  let version = 0;
  let slug = null;
  let phase = 0;

  function snapshot() {
    const frames = SNAPSHOTS[slug] || placeholder(slug);
    const frame = frames[Math.min(phase, frames.length - 1)];
    return {
      version,
      scenario: slug,
      now_us: phase * 400000,
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
