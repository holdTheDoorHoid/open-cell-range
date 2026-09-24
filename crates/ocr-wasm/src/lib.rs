//! The wasm-bindgen surface the Open Cell Range site talks to.
//!
//! The whole front end talks to exactly one object, [`Engine`]. Its contract is
//! written down in `site/ENGINE-API.md`, and a JavaScript reference
//! implementation of that same contract lives in `site/js/engine-mock.js`, so the
//! site can be built without a Rust toolchain. Keep this surface and that
//! document in lockstep: if they disagree, fix the document first.
//!
//! Methods take and return JSON strings, so the JS boundary stays a single
//! serialisation contract rather than a wide typed FFI.
//!
//! ## Implementer notes (stubbed; fill the bodies)
//! - Build the world from `ocr_scenario::build`, drive it with `ocr_air`/`
//!   ocr_attack`, observe with `ocr_detect`, and serialise a state snapshot.
//! - This is the integration crate; wire it last, once the libraries are real.

use wasm_bindgen::prelude::*;

/// The one object the site talks to. See `site/ENGINE-API.md`.
#[wasm_bindgen]
pub struct Engine {
    // Holds the loaded scenario, world, monitor and a version counter.
    #[allow(dead_code)]
    version: u32,
}

#[wasm_bindgen]
impl Engine {
    /// Create an engine with no scenario loaded.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Engine {
        Engine { version: 0 }
    }

    /// JSON array of `{slug, title, brief, track}` for every scenario.
    #[wasm_bindgen(js_name = listScenarios)]
    pub fn list_scenarios(&self) -> String {
        unimplemented!("serialise scenario catalogue")
    }

    /// Load a scenario by slug; returns the initial state snapshot as JSON.
    pub fn load(&mut self, slug: &str) -> String {
        let _ = slug;
        unimplemented!("build scenario, reset world/monitor")
    }

    /// Run a named attacker actor against the loaded world; returns a snapshot.
    #[wasm_bindgen(js_name = runAttack)]
    pub fn run_attack(&mut self, attacker_id: &str) -> String {
        let _ = attacker_id;
        unimplemented!("run attacker, re-observe, re-evaluate flags")
    }

    /// Advance the virtual clock; returns a snapshot.
    pub fn step(&mut self, dt_us: u32) -> String {
        let _ = dt_us;
        unimplemented!("world.step + observe")
    }

    /// Reset the loaded scenario to its initial world.
    pub fn reset(&mut self) -> String {
        unimplemented!("rebuild loaded scenario")
    }

    /// The current state snapshot as JSON: cells, UE, recent air events,
    /// monitor findings and flag states. Shape is documented in ENGINE-API.md.
    pub fn state(&self) -> String {
        unimplemented!("serialise current snapshot")
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}
