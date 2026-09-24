// app.js — the only file that imports the engine. Flip this line to swap the
// real wasm engine for the JavaScript reference one (see ENGINE-API.md).
import { createEngine } from './engine-wasm.js';
// import { createEngine } from './engine-mock.js';

// Everything below this line is UI-only bookkeeping: local flag-capture
// history (for the guided course's completed-count and the workshop
// scoreboard) and static reference copy (course framing text, instructor
// notes). Neither module talks to the engine — the import above stays the
// only engine seam in the site, exactly as ENGINE-API.md requires.
import * as progress from './progress.js';
import { framingFor, instructorNotesFor } from './curriculum-notes.js';

// engine-wasm.js loads the WebAssembly module and, if it is not present (e.g. a
// checkout with no `site/pkg` build), transparently falls back to the reference
// engine, so this await resolves either way.
const engine = await createEngine();
const $ = (id) => document.getElementById(id);

// The full catalogue, fetched once. `listScenarios()` returns it in teaching
// order (ENGINE-API.md), which is also the guided course's lesson order — the
// course does not maintain a second, separately-hardcoded ordering.
const ALL_SCENARIOS = engine.listScenarios();

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
let courseIndex = 0;

function renderScenarios() {
  const host = $('scenario-groups');
  host.innerHTML = '';

  for (const track of TRACK_ORDER) {
    const inTrack = ALL_SCENARIOS.filter((s) => s.track === track);
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
  const s = ALL_SCENARIOS.find((x) => x.slug === slug);
  currentSlug = slug;
  currentTitle = s.title;
  markActiveScenario();
  syncCourseToSlug(slug);
  renderInstructorNotes();

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
  $('tinker-readout').textContent =
    `Engine version ${snap.version} · virtual clock at ${(snap.now_us / 1000).toFixed(0)} ms.`;

  // Local-only bookkeeping (never fed back into the engine): record any flag
  // this snapshot says is captured, then refresh everything that reads that
  // record back — the course's completed-count and the workshop scoreboard.
  progress.recordSnapshot(currentSlug, snap);
  refreshCompletedCount();
  renderScoreboard();
}

// ---------------------------------------------------------------------------
// Guided course — a fixed walk through ALL_SCENARIOS in the engine's own
// teaching order. It never runs anything itself; "Open this lesson" just
// calls the same load(slug) the free catalogue calls. Prev/Next only move a
// client-side pointer and are cheap and idempotent at either end (clamped,
// never disabled) — consistent with Run/Reset already being safe to click
// repeatedly (see docs/UI.md).
// ---------------------------------------------------------------------------

function renderCourse() {
  const n = ALL_SCENARIOS.length;
  const lesson = ALL_SCENARIOS[courseIndex];
  $('course-position').textContent = `Lesson ${courseIndex + 1} of ${n}`;
  $('course-framing').textContent = framingFor(lesson.slug) || lesson.brief;
  $('course-open').textContent = `Open “${lesson.title}” in the sandbox`;
  refreshCompletedCount();
}

function refreshCompletedCount() {
  const n = ALL_SCENARIOS.length;
  let done = 0;
  for (const s of ALL_SCENARIOS) if (progress.isScenarioComplete(s.slug)) done++;
  $('course-completed').textContent = `${done}/${n} lessons complete`;
}

// Keep "Lesson N of 9" honest: whichever drill is actually loaded — via the
// course buttons or the free catalogue — is what the course reports as the
// current lesson. The course never has its own idea of "current drill" that
// could disagree with what's on screen.
function syncCourseToSlug(slug) {
  const idx = ALL_SCENARIOS.findIndex((s) => s.slug === slug);
  if (idx !== -1) {
    courseIndex = idx;
    renderCourse();
  }
}

$('course-prev').addEventListener('click', () => {
  courseIndex = Math.max(0, courseIndex - 1);
  renderCourse();
});
$('course-next').addEventListener('click', () => {
  courseIndex = Math.min(ALL_SCENARIOS.length - 1, courseIndex + 1);
  renderCourse();
});
$('course-open').addEventListener('click', () => load(ALL_SCENARIOS[courseIndex].slug));

// ---------------------------------------------------------------------------
// Tinker / sandbox controls — the two extra things the engine contract
// supports beyond Run/Reset: stepping the virtual clock, and a one-click
// "reload this scenario from scratch and immediately run its attack again."
// Both are labelled by exactly what they call; see ENGINE-API.md for step()'s
// actual contract (it advances the clock — it does not itself animate new
// messages in the reference engine).
// ---------------------------------------------------------------------------

$('step-btn').addEventListener('click', () => {
  if (!currentSlug) return;
  const dtUs = Number($('step-amount').value);
  render(engine.step(dtUs));
});

$('replay-btn').addEventListener('click', () => {
  if (!currentSlug) return;
  engine.load(currentSlug);
  render(engine.runAttack('headline'));
});

// ---------------------------------------------------------------------------
// Workshop / facilitator tools — a local (localStorage) CTF-style scoreboard,
// an optional instructor-notes overlay, and a print-friendly worksheet. None
// of this reaches a server; it's the same local-only posture DESIGN.md states
// for flags generally, extended to cover a whole workshop table.
// ---------------------------------------------------------------------------

function renderScoreboard() {
  const data = progress.allProgress();
  const total = progress.totalCaptured();
  const drillsWithProgress = Object.keys(data).length;
  $('scoreboard-summary').textContent = total
    ? `${total} flag${total === 1 ? '' : 's'} captured across ${drillsWithProgress}/${ALL_SCENARIOS.length} drills, in this browser only.`
    : `No flags captured yet in this browser. Run a drill's attack (or monitor) to capture its flag.`;

  $('scoreboard-list').innerHTML = ALL_SCENARIOS.map((s) => {
    const captured = progress.isScenarioComplete(s.slug);
    return `<li class="${captured ? 'captured' : 'not-captured'}">
        <span class="flag-badge">${captured ? '✓ Captured' : '○ Not yet'}</span>
        <b>${s.title}</b> <span class="muted">(${TRACK_LABEL[s.track]})</span>
      </li>`;
  }).join('');
}

$('scoreboard-reset').addEventListener('click', () => {
  const ok = window.confirm(
    "Clear this browser's captured-flag scoreboard? This only affects local storage on " +
    'this device and cannot be undone.',
  );
  if (!ok) return;
  progress.clearAll();
  renderScoreboard();
  refreshCompletedCount();
});

function renderInstructorNotes() {
  const panel = $('instructor-notes');
  const on = progress.getInstructorNotesEnabled();
  const notes = currentSlug ? instructorNotesFor(currentSlug) : [];
  if (!on || !notes.length) {
    panel.hidden = true;
    return;
  }
  $('instructor-notes-list').innerHTML = notes.map((n) => `<li>${n}</li>`).join('');
  panel.hidden = false;
}

$('instructor-notes-toggle').addEventListener('change', (e) => {
  progress.setInstructorNotesEnabled(e.target.checked);
  renderInstructorNotes();
});

function renderWorksheet() {
  $('worksheet-list').innerHTML = ALL_SCENARIOS.map((s, i) => `
    <li>
      <h2>${i + 1}. ${s.title} <small>(${TRACK_LABEL[s.track] || s.track})</small></h2>
      <p>${s.brief}</p>
      <p class="worksheet-framing">${framingFor(s.slug)}</p>
      <p class="worksheet-line">Flag captured? &#9633; yes &nbsp; &#9633; no &nbsp;&nbsp; Notes:</p>
      <p class="worksheet-rule"></p>
      <p class="worksheet-rule"></p>
    </li>`).join('');
}

$('print-worksheet').addEventListener('click', () => {
  renderWorksheet();
  window.print();
});

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

$('run').addEventListener('click', () => render(engine.runAttack('headline')));
$('reset').addEventListener('click', () => render(engine.reset()));

renderScenarios();
renderCourse();
renderScoreboard();
renderWorksheet();
$('instructor-notes-toggle').checked = progress.getInstructorNotesEnabled();
