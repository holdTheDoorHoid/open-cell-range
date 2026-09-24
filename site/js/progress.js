// progress.js — a small localStorage-backed record of flags this browser has
// captured, shared by the guided course (lesson "complete" state) and the
// workshop scoreboard (item 4/5 of the brief). This is pure UI-side
// bookkeeping: it never talks to the engine and never feeds a flag's
// `captured` state back into it. A flag here is only ever recorded *after*
// the engine's own snapshot said `captured: true` for it — see
// `recordSnapshot()` — so the local log can't drift into claiming something
// the engine itself didn't reach. Matches DESIGN.md's "CTF flags, local
// only": no backend, no accounts, nothing collected about anyone.

const STORAGE_KEY = 'ocr-progress-v1';
const NOTES_KEY = 'ocr-instructor-notes-v1';

function loadRaw() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    // Private browsing / storage disabled / corrupt value — treat as empty
    // rather than throwing, since nothing here is essential to using the site.
    return {};
  }
}

function saveRaw(data) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch {
    // Storage full or unavailable — silently drop. Progress tracking is a
    // convenience, not a requirement for the drills themselves to work.
  }
}

// Record every captured flag in a snapshot against its scenario. Safe to call
// on every render; already-captured entries just get their data refreshed
// (capturedAt is only set the first time).
export function recordSnapshot(scenarioSlug, snapshot) {
  if (!scenarioSlug || !snapshot || !Array.isArray(snapshot.flags)) return;
  const data = loadRaw();
  const bucket = data[scenarioSlug] || {};
  let changed = false;
  for (const f of snapshot.flags) {
    if (!f.captured) continue;
    if (!bucket[f.id]) {
      bucket[f.id] = { title: f.title, capturedAt: Date.now() };
      changed = true;
    }
  }
  if (changed) {
    data[scenarioSlug] = bucket;
    saveRaw(data);
  }
}

// All captured flag ids for one scenario, as a Set.
export function capturedFlagIds(scenarioSlug) {
  const data = loadRaw();
  return new Set(Object.keys(data[scenarioSlug] || {}));
}

// Has at least one flag been captured for this scenario? Used as "lesson
// complete" in the guided course — deliberately the same predicate the
// scoreboard uses, so the two never disagree about what "done" means.
export function isScenarioComplete(scenarioSlug) {
  return capturedFlagIds(scenarioSlug).size > 0;
}

// The full record, for rendering the scoreboard / worksheet.
export function allProgress() {
  return loadRaw();
}

export function totalCaptured() {
  const data = loadRaw();
  let n = 0;
  for (const slug of Object.keys(data)) n += Object.keys(data[slug]).length;
  return n;
}

export function clearAll() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
}

export function getInstructorNotesEnabled() {
  try {
    return localStorage.getItem(NOTES_KEY) === '1';
  } catch {
    return false;
  }
}

export function setInstructorNotesEnabled(on) {
  try {
    localStorage.setItem(NOTES_KEY, on ? '1' : '0');
  } catch {
    // ignore
  }
}
