#!/usr/bin/env node
// smoke.mjs — best-effort automated E2E smoke test for the Open Cell Range
// site (site/). Drives a real, already-installed Chrome/Chromium over CDP
// via `puppeteer-core` (NOT `puppeteer`: puppeteer-core ships no bundled
// browser, so `npm install` here never triggers the ~200MB Chromium
// download — see README.md for why that distinction matters offline).
//
// What this checks (per the brief):
//   1. The catalogue lists all 9 drills.
//   2. Loading a drill, then running it, changes engine-driven state.
//   3. The `nr-5g-suci-protects` drill does NOT leak the identity, even
//      after its attack runs.
//   4. No console errors / uncaught page exceptions occur along the way.
//
// This is a smoke test, not a full a11y or visual regression suite — see
// docs/ACCESSIBILITY.md for the accessibility audit and README.md for what
// this script deliberately does not cover (and how to check those by hand).
//
// Usage: node e2e/smoke.mjs
// Env:
//   CHROME_PATH / PUPPETEER_EXECUTABLE_PATH  — override the browser binary.
//   E2E_SITE_DIR                              — override the site/ path.
//   E2E_KEEP_OPEN=1                            — leave the browser open on
//                                                failure, for debugging.

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const SITE_DIR = resolve(process.env.E2E_SITE_DIR || join(HERE, '..', 'site'));

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.wasm': 'application/wasm',
  '.map': 'application/json; charset=utf-8',
};

// ---------------------------------------------------------------------------
// A tiny static file server for site/ — no extra dependency, no reliance on
// `python3` being installed, and no fixed port (so it never collides with a
// server a human already has open for manual verification).
// ---------------------------------------------------------------------------
function startStaticServer(rootDir) {
  const server = createServer(async (req, res) => {
    try {
      const urlPath = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
      let rel = urlPath === '/' ? '/index.html' : urlPath;
      const filePath = normalize(join(rootDir, rel));
      if (!filePath.startsWith(rootDir)) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
      }
      const st = await stat(filePath).catch(() => null);
      if (!st || !st.isFile()) {
        res.writeHead(404);
        res.end('Not found: ' + rel);
        return;
      }
      const body = await readFile(filePath);
      res.writeHead(200, { 'content-type': MIME[extname(filePath)] || 'application/octet-stream' });
      res.end(body);
    } catch (err) {
      res.writeHead(500);
      res.end('Server error: ' + (err && err.message));
    }
  });
  return new Promise((resolveP, rejectP) => {
    server.on('error', rejectP);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolveP({ server, port, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

// ---------------------------------------------------------------------------
// Locate a Chrome/Chromium binary already on this machine. puppeteer-core
// has no "download a browser" fallback by design — that's the point.
// ---------------------------------------------------------------------------
async function findChrome() {
  const candidates = [
    process.env.PUPPETEER_EXECUTABLE_PATH,
    process.env.CHROME_PATH,
    '/usr/bin/google-chrome-stable',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    '/snap/bin/chromium',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  ].filter(Boolean);
  for (const c of candidates) {
    const st = await stat(c).catch(() => null);
    if (st && st.isFile()) return c;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Small assertion helper — collects failures instead of throwing on the
// first one, so one bad assertion doesn't hide the rest of the report.
// ---------------------------------------------------------------------------
const failures = [];
function check(label, cond, detail) {
  if (cond) {
    console.log(`  PASS  ${label}`);
  } else {
    console.log(`  FAIL  ${label}${detail ? ' — ' + detail : ''}`);
    failures.push(label);
  }
}

async function main() {
  const chromePath = await findChrome();
  if (!chromePath) {
    console.error(
      'No Chrome/Chromium binary found (checked CHROME_PATH, PUPPETEER_EXECUTABLE_PATH, ' +
        'and common install paths). This script deliberately does not download one — see ' +
        'e2e/README.md for the manual checklist instead.',
    );
    process.exit(2);
  }
  console.log(`Using browser: ${chromePath}`);

  const siteStat = await stat(join(SITE_DIR, 'index.html')).catch(() => null);
  if (!siteStat) {
    console.error(`Could not find ${join(SITE_DIR, 'index.html')} — set E2E_SITE_DIR if site/ has moved.`);
    process.exit(2);
  }

  const { server, port, baseUrl } = await startStaticServer(SITE_DIR);
  console.log(`Serving ${SITE_DIR} at ${baseUrl}`);

  let puppeteer;
  try {
    ({ default: puppeteer } = await import('puppeteer-core'));
  } catch (err) {
    console.error(
      'puppeteer-core is not installed. Run `npm install` inside e2e/ first ' +
        '(it installs only the driver, not a browser — see README.md).',
    );
    server.close();
    process.exit(2);
  }

  const browser = await puppeteer.launch({
    executablePath: chromePath,
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });

  const consoleErrors = [];
  const pageErrors = [];

  try {
    const page = await browser.newPage();
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
    page.on('pageerror', (err) => pageErrors.push(String(err)));

    console.log('\n1. Loading the site...');
    await page.goto(`${baseUrl}/index.html`, { waitUntil: 'networkidle0', timeout: 30000 });
    await page.waitForSelector('#scenario-groups .scenario', { timeout: 10000 });

    console.log('\n2. Catalogue contents');
    const slugs = await page.$$eval('#scenario-groups .scenario', (els) =>
      els.map((el) => el.dataset.slug),
    );
    check('catalogue lists exactly 9 drills', slugs.length === 9, `found ${slugs.length}: ${slugs.join(', ')}`);
    check(
      'nr-5g-suci-protects is one of them',
      slugs.includes('nr-5g-suci-protects'),
      `slugs were: ${slugs.join(', ')}`,
    );

    console.log('\n3. Loading a drill changes state (gsm-2g-imsi-catch)');
    await page.click('.scenario[data-slug="gsm-2g-imsi-catch"]');
    await page.waitForSelector('#stage:not([hidden])', { timeout: 5000 });
    const statusAfterLoad = await page.$eval('#status', (el) => el.textContent.trim());
    check('status text is populated after load()', statusAfterLoad.length > 0, `got: "${statusAfterLoad}"`);

    console.log('\n4. Running the attack changes state further');
    await page.click('#run');
    // The status line is re-rendered synchronously by app.js's render(), but
    // give the engine call (real wasm or mock) a moment either way.
    await page.waitForFunction(
      (prev) => document.getElementById('status').textContent.trim() !== prev,
      { timeout: 5000 },
      statusAfterLoad,
    ).catch(() => {});
    const statusAfterRun = await page.$eval('#status', (el) => el.textContent.trim());
    const imsiLeakedAfterRun = await page.$eval('#ue', (el) => el.textContent.includes('leaked'));
    check(
      'running the attack changes the status line',
      statusAfterRun !== statusAfterLoad,
      `before: "${statusAfterLoad}" / after: "${statusAfterRun}"`,
    );
    check(
      'gsm-2g-imsi-catch leaks the identity once run (sanity check on the check below)',
      imsiLeakedAfterRun,
      `#ue text: "${await page.$eval('#ue', (el) => el.textContent.trim())}"`,
    );

    console.log('\n5. nr-5g-suci-protects does NOT leak, even after its attack runs');
    await page.click('.scenario[data-slug="nr-5g-suci-protects"]');
    await page.waitForSelector('#stage:not([hidden])', { timeout: 5000 });
    await page.click('#run');
    await page.waitForFunction(
      () => document.getElementById('status').textContent.includes('Permanent identity'),
      { timeout: 5000 },
    ).catch(() => {});
    const suciUeText = await page.$eval('#ue', (el) => el.textContent.trim());
    const suciStatusText = await page.$eval('#status', (el) => el.textContent.trim());
    check(
      'nr-5g-suci-protects UE panel says "protected", not "leaked"',
      suciUeText.includes('protected') && !suciUeText.includes('leaked'),
      `#ue text: "${suciUeText}"`,
    );
    check(
      'nr-5g-suci-protects status line says the identity is protected',
      suciStatusText.includes('Permanent identity protected'),
      `#status text: "${suciStatusText}"`,
    );

    console.log('\n6. Console cleanliness');
    check('no console.error messages', consoleErrors.length === 0, consoleErrors.join(' | '));
    check('no uncaught page exceptions', pageErrors.length === 0, pageErrors.join(' | '));
  } finally {
    if (failures.length && process.env.E2E_KEEP_OPEN === '1') {
      console.log('\nE2E_KEEP_OPEN=1 set — leaving the browser open for inspection. Ctrl+C to exit.');
      await new Promise(() => {}); // hang forever; user kills the process
    } else {
      await browser.close();
      server.close();
    }
  }
}

main()
  .then(() => {
    console.log(`\n${failures.length === 0 ? 'ALL CHECKS PASSED' : `${failures.length} CHECK(S) FAILED`}`);
    process.exit(failures.length === 0 ? 0 : 1);
  })
  .catch((err) => {
    console.error('\nSmoke test crashed:', err);
    process.exit(2);
  });
