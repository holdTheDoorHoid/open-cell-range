// app.js — the only file that imports the engine. Flip this line to swap the
// JavaScript reference engine for the real wasm one (see ENGINE-API.md).
import { createEngine } from './engine-mock.js';
// import { createEngine } from './engine-wasm.js';

const engine = createEngine();
const $ = (id) => document.getElementById(id);

const TRACK_ORDER = ['2g', '4g', '5g', 'defend'];
const TRACK_LABEL = { '2g': '2G', '4g': '4G', '5g': '5G', defend: 'Defend' };
const TRACK_HEADING = {
  '2g': '2G / GSM — broken by design',
  '4g': '4G / LTE — mutual auth, and the gaps that survive it',
  '5g': '5G / NR — SUCI fixes it, mostly',
  defend: 'Defend — watch the same air as a monitor',
};
// The button that runs the drill is named for what happens: for the attack
// tracks the learner is standing up an attacker; for the defend track the
// world is already attacked and the learner is running the passive monitor.
const RUN_LABEL = {
  '2g': 'Run the attack', '4g': 'Run the attack', '5g': 'Run the attack',
  defend: 'Run the monitor',
};

// Severity and flag state are never colour-only: every badge below pairs a
// shape/icon with the word itself, so the meaning survives colour-vision
// deficiency and greyscale printing alike.
const SEVERITY_ICON = { High: '⛔', Medium: '▲', Low: '◆', Info: 'ℹ' };
const DIR_LABEL = {
  net_to_ue: '↓ network → phone',
  ue_to_net: '↑ phone → network',
  observed: '• observed',
};

let currentSlug = null;
let currentTitle = '';

function renderScenarios() {
  const scenarios = engine.listScenarios();
  const host = $('scenario-groups');
  host.innerHTML = '';

  for (const track of TRACK_ORDER) {
    const inTrack = scenarios.filter((s) => s.track === track);
    if (!inTrack.length) continue;

    const section = document.createElement('section');
    section.className = `track-group track-group-${track}`;
    section.setAttribute('aria-labelledby', `track-heading-${track}`);

    const h3 = document.createElement('h3');
    h3.id = `track-heading-${track}`;
    h3.textContent = TRACK_HEADING[track] || TRACK_LABEL[track];
    section.appendChild(h3);

    const group = document.createElement('div');
    group.className = 'track-row';
    group.setAttribute('role', 'group');
    group.setAttribute('aria-label', `${TRACK_LABEL[track]} drills`);

    for (const s of inTrack) {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'scenario';
      b.dataset.slug = s.slug;
      b.setAttribute('aria-pressed', 'false');
      b.innerHTML = `
        <span class="track-badge track-${s.track}">${TRACK_LABEL[s.track]}</span>
        <span class="scenario-title">${s.title}</span>
        <span class="scenario-brief">${s.brief}</span>`;
      b.addEventListener('click', () => load(s.slug));
      group.appendChild(b);
    }

    section.appendChild(group);
    host.appendChild(section);
  }
}

function markActiveScenario() {
  for (const b of document.querySelectorAll('#scenario-groups .scenario')) {
    const active = b.dataset.slug === currentSlug;
    b.classList.toggle('active', active);
    b.setAttribute('aria-pressed', active ? 'true' : 'false');
  }
}

function load(slug) {
  const snap = engine.load(slug);
  const s = engine.listScenarios().find((x) => x.slug === slug);
  currentSlug = slug;
  currentTitle = s.title;
  markActiveScenario();

  $('stage').hidden = false;
  $('stage-title').textContent = s.title;
  $('stage-brief').textContent = s.brief;
  $('run').textContent = RUN_LABEL[s.track] || 'Run the attack';
  render(snap);
  $('stage').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function cellItem(c, campedOn) {
  const camped = campedOn === c.id;
  return `<li class="${camped ? 'camped-cell' : ''}">
      <span class="cell-id">cell ${c.id}</span>
      <span class="cell-rat">${c.rat.toUpperCase()}</span>
      <span class="cell-plmn">${c.plmn}</span>
      <span class="cell-signal">${c.signal_dbm} dBm</span>
      <span class="cell-area">area ${c.area_code}</span>
      ${camped ? '<span class="camped-badge">📶 phone camped here</span>' : ''}
    </li>`;
}

// A boolean rendered as icon + colour + a word that names the actual state
// ("leaked"/"protected") rather than a bare yes/no — so the meaning survives
// colour-vision deficiency and reads correctly even out of context.
function stateBadge(isBad, badWord, goodWord) {
  return isBad
    ? `<b class="bad">⚠ ${badWord}</b>`
    : `<b class="good">✓ ${goodWord}</b>`;
}

function statusText(snap) {
  if (!snap.events.length) {
    return `Loaded “${currentTitle}”. Nothing has happened yet — the air is quiet.`;
  }
  const identity = snap.ue.imsi_leaked ? 'leaked' : 'protected';
  const captured = snap.flags.filter((f) => f.captured).length;
  const n = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;
  return `${n(snap.events.length, 'message')} on the air. `
    + `Permanent identity ${identity}. `
    + `${n(snap.findings.length, 'finding')} raised. `
    + `${captured}/${snap.flags.length} ${snap.flags.length === 1 ? 'flag' : 'flags'} captured.`;
}

function render(snap) {
  $('cells').innerHTML = snap.cells.map((c) => cellItem(c, snap.ue.camped_on)).join('')
    || '<li class="muted">no cells yet</li>';

  const ue = snap.ue;
  $('ue').innerHTML = `
     <div>Camped on: <b>${ue.camped_on ?? '—'}</b> ${ue.camped_rat ? `(${ue.camped_rat.toUpperCase()})` : ''}</div>
     <div>Permanent identity: ${stateBadge(ue.imsi_leaked, 'leaked', 'protected')}</div>
     <div>Cipher: ${stateBadge(ue.null_cipher_active, 'none — A5/0 forced', 'network default')}</div>`;

  $('events').innerHTML = snap.events.map((e) => `
      <li>
        <div class="event-head">
          <code>${(e.t_us / 1000).toFixed(0)} ms</code>
          <span class="dir dir-${e.dir}">${DIR_LABEL[e.dir] || e.dir}</span>
          <b>${e.msg}</b>
        </div>
        <div class="muted">${e.summary}</div>
      </li>`).join('')
    || '<li class="muted">no messages yet — run the drill to see the air log fill in</li>';

  $('findings').innerHTML = snap.findings.map((f) => `
      <li class="sev sev-${f.severity.toLowerCase()}">
        <span class="sev-badge">${SEVERITY_ICON[f.severity] || ''} ${f.severity}</span>
        <b>${f.kind}</b>
        <div class="muted">${f.detail}</div>
      </li>`).join('')
    || '<li class="muted">the monitor has nothing to report yet</li>';

  $('flags').innerHTML = snap.flags.map((f) => `
      <li class="${f.captured ? 'captured' : 'not-captured'}">
        <span class="flag-badge">${f.captured ? '✓ Captured' : '○ Not yet'}</span>
        <b>${f.title}</b>
        ${f.captured ? '' : `<div class="muted">${f.hint}</div>`}
      </li>`).join('');

  $('status').textContent = statusText(snap);
}

$('run').addEventListener('click', () => render(engine.runAttack('headline')));
$('reset').addEventListener('click', () => render(engine.reset()));

renderScenarios();
