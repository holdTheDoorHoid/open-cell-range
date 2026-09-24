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
//! ## What the engine is
//!
//! A small state machine over one loaded [`Scenario`]:
//! - `load(slug)` builds the scenario's **clean baseline** world (the phone on the
//!   real network, nothing attacked yet) and clears `attacked`.
//! - `runAttack` runs the scenario's headline attacker
//!   ([`Scenario::run_headline`]) and sets `attacked`.
//! - the snapshot is derived from `(scenario.world, attacked)` every call.
//!
//! ## The two rules that make the snapshot honest
//!
//! - **`attacked` gates `findings`.** Findings are the passive monitor's
//!   conclusions; before the learner runs the drill the monitor has not run, so
//!   `findings` is empty and the "before" state stays clean. On `runAttack` a
//!   FRESH [`Monitor`] observes the whole air and its findings are reported. This
//!   is exactly the "click to run the monitor reveals findings" behaviour the
//!   defend drill teaches.
//! - **Ground truth never crosses the boundary.** `Cell::legitimate` is the
//!   answer the learner must infer; it is deliberately absent from every cell in
//!   the snapshot (see `site/ENGINE-API.md`).

use ocr_air::{describe, Direction, Payload, Rat, World};
use ocr_detect::{Monitor, Severity};
use ocr_identity::Plmn;
use ocr_scenario::{build, Scenario, ScenarioId};
use wasm_bindgen::prelude::*;

// ---- small mappings from engine types to the JSON contract strings ----------

/// Radio access technology as the contract spells it.
fn rat_str(rat: Rat) -> &'static str {
    match rat {
        Rat::Gsm => "gsm",
        Rat::Lte => "lte",
        Rat::Nr => "nr",
    }
}

/// Message direction as the contract spells it.
fn dir_str(dir: Direction) -> &'static str {
    match dir {
        Direction::NetToUe => "net_to_ue",
        Direction::UeToNet => "ue_to_net",
        Direction::Observed => "observed",
    }
}

/// Finding severity as the contract spells it.
fn severity_str(sev: Severity) -> &'static str {
    match sev {
        Severity::Info => "Info",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
    }
}

/// Render a PLMN as `"MCC-MNC"`, the MNC left-padded to its own length so a
/// two- or three-digit MNC is preserved (see `site/ENGINE-API.md`).
fn plmn_str(p: &Plmn) -> String {
    format!("{}-{:0width$}", p.mcc, p.mnc, width = p.mnc_len as usize)
}

/// A SHORT display label for one air message, derived from its [`Payload`]
/// variant — the bold headline the UI shows next to each event. The long,
/// sentence-form gloss is [`describe`] (used for `summary`); this is the terse
/// tag, e.g. `IdentityRequest(IMSI)`, `CipherModeCommand(A5/0)`,
/// `SystemInformation`, `AttachReject`, `RegistrationRequest(SUCI)`.
///
/// The match is exhaustive on purpose: if a per-generation crate grows a message
/// variant, this stops compiling until a label is chosen for it, rather than
/// silently emitting a wrong or empty tag.
fn msg_label(payload: &Payload) -> String {
    match payload {
        Payload::Gsm(m) => {
            use ocr_gsm::{GsmMessage as M, IdentityType, A5};
            match m {
                M::SystemInformation { .. } => "SystemInformation".into(),
                M::LocationUpdateRequest { tmsi: Some(_) } => "LocationUpdateRequest(TMSI)".into(),
                M::LocationUpdateRequest { tmsi: None } => "LocationUpdateRequest".into(),
                M::IdentityRequest { id_type } => match id_type {
                    IdentityType::Imsi => "IdentityRequest(IMSI)".into(),
                    IdentityType::Tmsi => "IdentityRequest(TMSI)".into(),
                    IdentityType::Imei => "IdentityRequest(IMEI)".into(),
                },
                M::IdentityResponse { imsi: Some(_) } => "IdentityResponse(IMSI)".into(),
                M::IdentityResponse { imsi: None } => "IdentityResponse".into(),
                M::AuthenticationRequest { .. } => "AuthenticationRequest".into(),
                M::AuthenticationResponse { .. } => "AuthenticationResponse".into(),
                M::CipherModeCommand { algorithm } => match algorithm {
                    A5::A5_0 => "CipherModeCommand(A5/0)".into(),
                    A5::A5_1 => "CipherModeCommand(A5/1)".into(),
                    A5::A5_3 => "CipherModeCommand(A5/3)".into(),
                },
                M::CipherModeComplete => "CipherModeComplete".into(),
                M::LocationUpdateAccept { .. } => "LocationUpdateAccept".into(),
                M::LocationUpdateReject { .. } => "LocationUpdateReject".into(),
            }
        }
        Payload::LteNas(m) => {
            use ocr_lte::{LteNasMessage as M, NasAlgorithm};
            match m {
                M::AttachRequest { guti: Some(_) } => "AttachRequest(GUTI)".into(),
                M::AttachRequest { guti: None } => "AttachRequest".into(),
                M::IdentityRequest => "IdentityRequest(IMSI)".into(),
                M::IdentityResponse { imsi: Some(_) } => "IdentityResponse(IMSI)".into(),
                M::IdentityResponse { imsi: None } => "IdentityResponse".into(),
                M::AuthenticationRequest { .. } => "AuthenticationRequest".into(),
                M::AuthenticationResponse { .. } => "AuthenticationResponse".into(),
                M::AuthenticationFailureSyncFailure { .. } => {
                    "AuthenticationFailure(SyncFailure)".into()
                }
                M::AuthenticationFailureMacFailure => "AuthenticationFailure(MacFailure)".into(),
                M::SecurityModeCommand { algorithm } => match algorithm {
                    NasAlgorithm::EEA0_EIA0 => "SecurityModeCommand(EEA0/EIA0)".into(),
                    NasAlgorithm::EEA1_EIA1 => "SecurityModeCommand(EEA1/EIA1)".into(),
                    NasAlgorithm::EEA2_EIA2 => "SecurityModeCommand(EEA2/EIA2)".into(),
                },
                M::SecurityModeComplete => "SecurityModeComplete".into(),
                M::AttachAccept { .. } => "AttachAccept".into(),
                M::AttachReject { .. } => "AttachReject".into(),
                M::TrackingAreaUpdateReject { .. } => "TrackingAreaUpdateReject".into(),
                M::Paging { by_imsi: true } => "Paging(IMSI)".into(),
                M::Paging { by_imsi: false } => "Paging(S-TMSI)".into(),
            }
        }
        Payload::LteRrc(m) => {
            use ocr_lte::LteRrcMessage as M;
            match m {
                M::SystemInformation { .. } => "SystemInformation".into(),
                M::ConnectionRequest => "ConnectionRequest".into(),
                M::ConnectionSetup => "ConnectionSetup".into(),
                M::ConnectionReject { .. } => "ConnectionReject".into(),
                M::MeasurementReport => "MeasurementReport".into(),
            }
        }
        Payload::NrNas(m) => {
            use ocr_nr::{AuthFailureCause, NrAlgorithm, NrNasMessage as M};
            match m {
                M::RegistrationRequest { suci: Some(s), .. } => {
                    if s.is_protected() {
                        "RegistrationRequest(SUCI)".into()
                    } else {
                        "RegistrationRequest(SUCI, scheme=null)".into()
                    }
                }
                M::RegistrationRequest { suci: None, .. } => "RegistrationRequest(5G-GUTI)".into(),
                M::IdentityRequestSuci => "IdentityRequest(SUCI)".into(),
                M::IdentityResponseSuci { suci } => {
                    if suci.is_protected() {
                        "IdentityResponse(SUCI)".into()
                    } else {
                        "IdentityResponse(SUCI, scheme=null)".into()
                    }
                }
                M::AuthenticationRequest { .. } => "AuthenticationRequest".into(),
                M::AuthenticationResponse { .. } => "AuthenticationResponse".into(),
                M::AuthenticationFailure { cause, .. } => match cause {
                    AuthFailureCause::MacFailure => "AuthenticationFailure(MacFailure)".into(),
                    AuthFailureCause::SynchFailure => "AuthenticationFailure(SynchFailure)".into(),
                },
                M::SecurityModeCommand { algorithm } => match algorithm {
                    NrAlgorithm::NEA0_NIA0 => "SecurityModeCommand(NEA0/NIA0)".into(),
                    NrAlgorithm::NEA1_NIA1 => "SecurityModeCommand(NEA1/NIA1)".into(),
                    NrAlgorithm::NEA2_NIA2 => "SecurityModeCommand(NEA2/NIA2)".into(),
                },
                M::SecurityModeComplete => "SecurityModeComplete".into(),
                M::RegistrationAccept { .. } => "RegistrationAccept".into(),
                M::RegistrationReject { .. } => "RegistrationReject".into(),
            }
        }
        Payload::NrRrc(m) => {
            use ocr_nr::NrRrcMessage as M;
            match m {
                M::SystemInformation { .. } => "SystemInformation".into(),
                M::SetupRequest => "SetupRequest".into(),
                M::Setup => "Setup".into(),
                M::Reject { .. } => "Reject".into(),
            }
        }
    }
}

/// The one object the site talks to. See `site/ENGINE-API.md`.
#[wasm_bindgen]
pub struct Engine {
    /// The scenario currently loaded, if any.
    scenario: Option<Scenario>,
    /// Bumped on every state-changing call so the UI can detect staleness.
    version: u32,
    /// Whether the headline attack has been run on the loaded scenario. Gates
    /// whether the passive monitor's findings appear in the snapshot.
    attacked: bool,
}

#[wasm_bindgen]
impl Engine {
    /// Create an engine with no scenario loaded.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Engine {
        Engine {
            scenario: None,
            version: 0,
            attacked: false,
        }
    }

    /// JSON array of `{slug, title, brief, track}` for every scenario, in
    /// teaching order.
    #[wasm_bindgen(js_name = listScenarios)]
    pub fn list_scenarios(&self) -> String {
        let catalogue: Vec<serde_json::Value> = ScenarioId::all()
            .iter()
            .map(|id| {
                // title/brief are built content; slug/track are id metadata.
                let s = build(*id);
                serde_json::json!({
                    "slug": id.slug(),
                    "title": s.title,
                    "brief": s.brief,
                    "track": id.track(),
                })
            })
            .collect();
        serde_json::Value::Array(catalogue).to_string()
    }

    /// Load a scenario by slug: build its clean baseline world, clear the attack
    /// state, and return the initial snapshot as JSON.
    pub fn load(&mut self, slug: &str) -> String {
        match ScenarioId::all().iter().find(|id| id.slug() == slug) {
            Some(id) => {
                self.scenario = Some(build(*id));
                self.attacked = false;
                self.version += 1;
            }
            None => {
                // Unknown slug: clear the loaded scenario so the snapshot is a
                // valid, empty world rather than a stale one.
                self.scenario = None;
                self.attacked = false;
                self.version += 1;
            }
        }
        self.snapshot()
    }

    /// Run the loaded scenario's headline attacker against its world, mark the
    /// world attacked (so the monitor's findings appear), and return a snapshot.
    ///
    /// The `_attacker_id` argument is the site's single "run the drill" button;
    /// the engine always runs the loaded scenario's own headline attack.
    #[wasm_bindgen(js_name = runAttack)]
    pub fn run_attack(&mut self, _attacker_id: &str) -> String {
        if let Some(scenario) = &mut self.scenario {
            scenario.run_headline();
            self.attacked = true;
            self.version += 1;
        }
        self.snapshot()
    }

    /// Advance the virtual clock by `dt_us` microseconds and return a snapshot.
    pub fn step(&mut self, dt_us: u32) -> String {
        if let Some(scenario) = &mut self.scenario {
            scenario.world.step(dt_us as u64);
            self.version += 1;
        }
        self.snapshot()
    }

    /// Rebuild the loaded scenario to its clean baseline, clearing the attack.
    pub fn reset(&mut self) -> String {
        if let Some(scenario) = &self.scenario {
            let id = scenario.id;
            self.scenario = Some(build(id));
            self.attacked = false;
            self.version += 1;
        }
        self.snapshot()
    }

    /// The current state snapshot as JSON, changing nothing. Shape is documented
    /// in `site/ENGINE-API.md`.
    pub fn state(&self) -> String {
        self.snapshot()
    }
}

impl Engine {
    /// Serialise the current world (or an empty world when nothing is loaded)
    /// into the snapshot contract. Private: not part of the JS surface.
    fn snapshot(&self) -> String {
        let scenario = match &self.scenario {
            Some(s) => s,
            None => {
                // No scenario loaded: a valid, empty snapshot.
                return serde_json::json!({
                    "version": self.version,
                    "scenario": serde_json::Value::Null,
                    "now_us": 0,
                    "cells": [],
                    "ue": {
                        "camped_on": serde_json::Value::Null,
                        "camped_rat": serde_json::Value::Null,
                        "imsi_leaked": false,
                        "null_cipher_active": false,
                    },
                    "events": [],
                    "findings": [],
                    "flags": [],
                })
                .to_string();
            }
        };
        let world: &World = &scenario.world;

        // The passive monitor only runs once the learner has run the drill; until
        // then it has observed nothing, so it has no findings and captures no
        // monitor-reading flag. This keeps the "before" state clean.
        let mut monitor = Monitor::new();
        if self.attacked {
            monitor.observe_all(world.events());
        }

        // Cells — NEVER the ground-truth `legitimate` field.
        let cells: Vec<serde_json::Value> = world
            .cells
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.id.0,
                    "rat": rat_str(c.rat),
                    "plmn": plmn_str(&c.plmn),
                    "signal_dbm": c.signal_dbm,
                    "area_code": c.area_code,
                })
            })
            .collect();

        let ue = serde_json::json!({
            "camped_on": world.ue.camped_on.map(|c| c.0),
            "camped_rat": world.ue.camped_rat.map(rat_str),
            "imsi_leaked": world.ue.imsi_leaked,
            "null_cipher_active": world.ue.null_cipher_active,
        });

        let events: Vec<serde_json::Value> = world
            .events()
            .iter()
            .map(|ev| {
                serde_json::json!({
                    "t_us": ev.t_us,
                    "rat": rat_str(ev.rat),
                    "cell": ev.cell.0,
                    "dir": dir_str(ev.dir),
                    "msg": msg_label(&ev.payload),
                    "summary": describe(ev),
                })
            })
            .collect();

        // Findings come straight from the monitor; empty unless attacked (the
        // monitor observed nothing in that case).
        let findings: Vec<serde_json::Value> = monitor
            .findings()
            .iter()
            .map(|f| {
                serde_json::json!({
                    "kind": f.kind.as_str(),
                    "severity": severity_str(f.severity),
                    "t_us": f.t_us,
                    "detail": f.detail,
                })
            })
            .collect();

        // Flags are evaluated on engine state via their own predicates, never on
        // user input — using the same monitor built above (empty when not
        // attacked, so a monitor-reading flag stays uncaptured until the drill runs).
        let flags: Vec<serde_json::Value> = scenario
            .flags
            .iter()
            .map(|flag| {
                serde_json::json!({
                    "id": flag.id,
                    "title": flag.title,
                    "captured": (flag.predicate)(world, &monitor),
                    "hint": flag.hint,
                })
            })
            .collect();

        serde_json::json!({
            "version": self.version,
            "scenario": scenario.id.slug(),
            "now_us": world.now_us,
            "cells": cells,
            "ue": ue,
            "events": events,
            "findings": findings,
            "flags": flags,
        })
        .to_string()
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Parse an engine method's JSON return into a `Value` for assertions.
    fn parse(json: &str) -> Value {
        serde_json::from_str(json).expect("engine methods return valid JSON")
    }

    #[test]
    fn list_scenarios_returns_seven_entries_with_all_fields() {
        let engine = Engine::new();
        let v = parse(&engine.list_scenarios());
        let arr = v.as_array().expect("listScenarios is a JSON array");
        assert_eq!(arr.len(), 7, "the range ships seven drills");
        for s in arr {
            assert!(s["slug"].is_string());
            assert!(s["title"].is_string() && !s["title"].as_str().unwrap().is_empty());
            assert!(s["brief"].is_string() && !s["brief"].as_str().unwrap().is_empty());
            assert!(matches!(
                s["track"].as_str().expect("track is a string"),
                "2g" | "4g" | "5g" | "defend"
            ));
        }
    }

    #[test]
    fn snapshot_has_the_contract_shape_and_never_leaks_ground_truth() {
        let mut engine = Engine::new();
        let v = parse(&engine.load("gsm-2g-imsi-catch"));
        assert_eq!(v["scenario"], "gsm-2g-imsi-catch");
        assert!(v["version"].is_number());
        assert!(v["now_us"].is_number());
        assert!(v["cells"].is_array());
        assert!(v["events"].is_array());
        assert!(v["findings"].is_array());
        assert!(v["flags"].is_array());

        let ue = &v["ue"];
        assert!(ue["imsi_leaked"].is_boolean());
        assert!(ue["null_cipher_active"].is_boolean());
        assert!(ue.get("camped_on").is_some());
        assert!(ue.get("camped_rat").is_some());

        for c in v["cells"].as_array().unwrap() {
            // `legitimate` is the answer the learner must infer — never sent.
            assert!(
                c.get("legitimate").is_none(),
                "cells must never carry the ground-truth `legitimate` field"
            );
            assert!(c["id"].is_number());
            assert!(matches!(c["rat"].as_str().unwrap(), "gsm" | "lte" | "nr"));
            assert!(c["plmn"].is_string());
            assert!(c["signal_dbm"].is_number());
            assert!(c["area_code"].is_number());
        }
    }

    #[test]
    fn before_the_attack_findings_are_empty_and_no_flag_captured() {
        let mut engine = Engine::new();
        let v = parse(&engine.load("gsm-2g-imsi-catch"));
        assert!(
            v["findings"].as_array().unwrap().is_empty(),
            "the monitor has not run yet, so there are no findings"
        );
        assert_eq!(v["ue"]["imsi_leaked"], false);
        assert!(v["flags"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["captured"] == Value::Bool(false)));
    }

    #[test]
    fn run_attack_leaks_the_imsi_reveals_findings_and_captures_the_flag() {
        let mut engine = Engine::new();
        engine.load("gsm-2g-imsi-catch");
        let v = parse(&engine.run_attack("headline"));

        assert_eq!(
            v["ue"]["imsi_leaked"], true,
            "the 2G catcher leaks the IMSI"
        );
        assert!(
            !v["findings"].as_array().unwrap().is_empty(),
            "running the drill reveals the monitor's findings"
        );
        assert!(
            v["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["captured"] == Value::Bool(true)),
            "at least one flag captures from engine state"
        );

        for f in v["findings"].as_array().unwrap() {
            assert!(f["kind"].is_string());
            assert!(matches!(
                f["severity"].as_str().unwrap(),
                "Info" | "Low" | "Medium" | "High"
            ));
            assert!(f["t_us"].is_number());
            assert!(f["detail"].is_string());
        }
        // version advanced across load + runAttack.
        assert!(v["version"].as_u64().unwrap() >= 2);
    }

    #[test]
    fn events_carry_a_short_msg_and_a_sentence_summary() {
        let mut engine = Engine::new();
        engine.load("gsm-2g-imsi-catch");
        let v = parse(&engine.run_attack("headline"));
        let events = v["events"].as_array().unwrap();
        assert!(!events.is_empty(), "the attack produces air events");
        for e in events {
            assert!(e["t_us"].is_number());
            assert!(matches!(e["rat"].as_str().unwrap(), "gsm" | "lte" | "nr"));
            assert!(e["cell"].is_number());
            assert!(matches!(
                e["dir"].as_str().unwrap(),
                "net_to_ue" | "ue_to_net" | "observed"
            ));
            assert!(!e["msg"].as_str().unwrap().is_empty());
            assert!(!e["summary"].as_str().unwrap().is_empty());
        }
    }

    #[test]
    fn nr_suci_protects_does_not_leak_yet_captures_its_flag() {
        let mut engine = Engine::new();
        engine.load("nr-5g-suci-protects");
        let v = parse(&engine.run_attack("headline"));
        assert_eq!(
            v["ue"]["imsi_leaked"], false,
            "Profile A SUCI conceals the SUPI even under attack"
        );
        assert!(
            v["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["captured"] == Value::Bool(true)),
            "the flag captures the identity STAYING protected"
        );
    }

    #[test]
    fn nr_null_scheme_leaks_the_supi() {
        let mut engine = Engine::new();
        engine.load("nr-5g-null-scheme");
        let v = parse(&engine.run_attack("headline"));
        assert_eq!(
            v["ue"]["imsi_leaked"], true,
            "the null protection scheme puts the SUPI on the air"
        );
    }

    #[test]
    fn defend_has_events_but_no_findings_until_the_monitor_runs() {
        let mut engine = Engine::new();
        let before = parse(&engine.load("defend-spot-the-catcher"));
        assert!(
            !before["events"].as_array().unwrap().is_empty(),
            "the defend world is already attacked before the learner arrives"
        );
        assert!(
            before["findings"].as_array().unwrap().is_empty(),
            "findings appear only once the passive monitor is run"
        );
        assert!(before["flags"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["captured"] == Value::Bool(false)));

        let after = parse(&engine.run_attack("headline"));
        assert!(
            !after["findings"].as_array().unwrap().is_empty(),
            "running the monitor over the same air raises findings"
        );
        assert!(after["flags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["captured"] == Value::Bool(true)));
    }

    #[test]
    fn reset_rebuilds_the_clean_baseline() {
        let mut engine = Engine::new();
        engine.load("gsm-2g-imsi-catch");
        engine.run_attack("headline");
        let v = parse(&engine.reset());
        assert_eq!(v["ue"]["imsi_leaked"], false, "reset clears the attack");
        assert!(v["findings"].as_array().unwrap().is_empty());
        assert!(v["flags"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["captured"] == Value::Bool(false)));
    }

    #[test]
    fn state_changes_nothing() {
        let mut engine = Engine::new();
        engine.load("gsm-2g-imsi-catch");
        let a = parse(&engine.state());
        let b = parse(&engine.state());
        assert_eq!(a, b, "state() is a pure read");
    }

    #[test]
    fn unknown_slug_yields_a_valid_empty_snapshot() {
        let mut engine = Engine::new();
        let v = parse(&engine.load("does-not-exist"));
        assert_eq!(v["scenario"], Value::Null);
        assert!(v["cells"].as_array().unwrap().is_empty());
        assert!(v["events"].as_array().unwrap().is_empty());
        assert!(v["flags"].as_array().unwrap().is_empty());
        assert_eq!(v["ue"]["camped_on"], Value::Null);
    }
}
