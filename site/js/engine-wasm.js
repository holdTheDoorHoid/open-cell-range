// engine-wasm.js — the production loader for the real engine: crates/ocr-wasm
// compiled to WebAssembly with `wasm-pack build --target web --out-dir site/pkg`.
// It is the drop-in counterpart to engine-mock.js and honours the same contract
// (site/ENGINE-API.md), so app.js can swap one import line for the other.
//
// wasm-pack's `--target web` output is site/pkg/ocr_wasm.js: a module whose
// DEFAULT export is an async `init()` that fetches and instantiates the .wasm,
// alongside the `Engine` class. Every Engine method returns a JSON string across
// the wasm boundary, so we JSON.parse each result and hand callers the same plain
// objects the mock returns.
//
// Safety net: if site/pkg has not been built yet (e.g. a checkout with no wasm
// toolchain, or a Pages deploy where the build step was skipped), the dynamic
// import or init throws. We catch that, warn, and fall back to the JavaScript
// reference engine so the site still works.

export async function createEngine() {
  try {
    const wasm = await import('../pkg/ocr_wasm.js');
    // Instantiate the module (fetches ocr_wasm_bg.wasm next to ocr_wasm.js).
    await wasm.default();

    const engine = new wasm.Engine();

    // Wrap the wasm object so callers see parsed objects, never JSON strings.
    return {
      listScenarios: () => JSON.parse(engine.listScenarios()),
      load: (slug) => JSON.parse(engine.load(slug)),
      runAttack: (attackerId) => JSON.parse(engine.runAttack(attackerId)),
      step: (dtUs) => JSON.parse(engine.step(dtUs)),
      reset: () => JSON.parse(engine.reset()),
      state: () => JSON.parse(engine.state()),
    };
  } catch (err) {
    console.warn(
      'engine-wasm: the wasm engine could not be loaded (is site/pkg built? ' +
        'run `wasm-pack build crates/ocr-wasm --target web --out-dir ../../site/pkg`). ' +
        'Falling back to the JavaScript reference engine.',
      err,
    );
    const mock = await import('./engine-mock.js');
    return mock.createEngine();
  }
}
