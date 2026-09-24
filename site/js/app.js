// app.js — the only file that imports the engine. Flip this line to swap the
// JavaScript reference engine for the real wasm one (see ENGINE-API.md).
import { createEngine } from './engine-mock.js';
// import { createEngine } from './engine-wasm.js';

const engine = createEngine();
const $ = (id) => document.getElementById(id);
const TRACK_LABEL = { '2g': '2G', '4g': '4G', '5g': '5G', 'defend': 'Defend' };

function renderScenarios() {
  const nav = $('scenarios');
  nav.innerHTML = '';
  for (const s of engine.listScenarios()) {
    const b = document.createElement('button');
    b.className = 'scenario';
    b.innerHTML = `<span class="track track-${s.track}">${TRACK_LABEL[s.track] || s.track}</span> ${s.title}`;
    b.onclick = () => { load(s.slug); };
    nav.appendChild(b);
  }
}

function load(slug) {
  const snap = engine.load(slug);
  const s = engine.listScenarios().find((x) => x.slug === slug);
  $('stage').hidden = false;
  $('stage-title').textContent = s.title;
  $('stage-brief').textContent = s.brief;
  render(snap);
}

function render(snap) {
  $('cells').innerHTML = snap.cells.map((c) =>
    `<li><b>cell ${c.id}</b> · ${c.rat.toUpperCase()} · ${c.plmn} · ${c.signal_dbm} dBm · area ${c.area_code}
      ${snap.ue.camped_on === c.id ? '<span class="camped">phone camped here</span>' : ''}</li>`).join('')
    || '<li class="muted">no cells yet</li>';

  const ue = snap.ue;
  $('ue').innerHTML =
    `<div>camped on: <b>${ue.camped_on ?? '—'}</b> (${ue.camped_rat ? ue.camped_rat.toUpperCase() : '—'})</div>
     <div>IMSI leaked: <b class="${ue.imsi_leaked ? 'bad' : 'good'}">${ue.imsi_leaked ? 'yes' : 'no'}</b></div>
     <div>null cipher: <b class="${ue.null_cipher_active ? 'bad' : 'good'}">${ue.null_cipher_active ? 'active' : 'off'}</b></div>`;

  $('events').innerHTML = snap.events.map((e) =>
    `<li><code>${(e.t_us / 1000).toFixed(0)} ms</code> <span class="dir dir-${e.dir}">${e.dir}</span>
      <b>${e.msg}</b><br><span class="muted">${e.summary}</span></li>`).join('')
    || '<li class="muted">no messages yet — run the attack</li>';

  $('findings').innerHTML = snap.findings.map((f) =>
    `<li class="sev sev-${f.severity.toLowerCase()}"><b>${f.severity}</b> · ${f.kind}<br>
      <span class="muted">${f.detail}</span></li>`).join('')
    || '<li class="muted">nothing flagged</li>';

  $('flags').innerHTML = snap.flags.map((f) =>
    `<li class="${f.captured ? 'captured' : ''}">${f.captured ? '✓' : '○'} <b>${f.title}</b>
      ${f.captured ? '' : `<br><span class="muted">${f.hint}</span>`}</li>`).join('');
}

$('run').onclick = () => render(engine.runAttack('headline'));
$('reset').onclick = () => render(engine.reset());

renderScenarios();
