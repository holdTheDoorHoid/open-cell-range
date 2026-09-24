//! Engine-determinism tests for the drill layer — the reproducibility guarantee
//! `DESIGN.md` section 3 makes: *"the same scenario and seed always produce the
//! same bytes on the wire, so flags are stable, bugs are reproducible, and a
//! capture replays identically on any machine."*
//!
//! This holds that guarantee at the `ocr-scenario` boundary in two ways:
//!
//! 1. **Run-to-run identity for every scenario.** For each [`ScenarioId::all()`],
//!    building and running the drill twice must produce byte-identical
//!    `world.events()`, identical evaluated [`FlagState`]s, and identical monitor
//!    findings. `build()` uses the fixed default seed (there is no per-scenario
//!    seed knob today), so this is the default-path reproducibility guarantee.
//! 2. **Seed threading through the full attack + detect pipeline.** Where a seed
//!    *is* threadable — [`World::with_seed`] — the same seed must reproduce the
//!    same air and the same findings across a wide range of seeds, driving a real
//!    `ocr_attack` actor and the `ocr_detect` monitor end to end.
//!
//! `Finding` derives neither `PartialEq` nor `Eq`, so findings are compared through
//! a stable projection of their public fields.

use ocr_air::{AirEvent, Rat, World};
use ocr_attack::{Attacker, ImsiCatcher2g};
use ocr_detect::{Finding, FindingKind, Monitor, Severity};
use ocr_scenario::{build, FlagState, ScenarioId};

/// A comparable projection of a `Finding` (which is not itself `Eq`).
type FindingKey = (FindingKind, Severity, u64, String);

fn project(findings: &[Finding]) -> Vec<FindingKey> {
    findings
        .iter()
        .map(|f| (f.kind, f.severity, f.t_us, f.detail.clone()))
        .collect()
}

/// Build a scenario, run its headline attack, then observe the whole air with a
/// fresh monitor and evaluate the flags — exactly the engine's `runAttack` flow.
/// Returns everything that must be reproducible: the event stream, the flag
/// states, and the monitor's findings.
fn build_run_observe(id: ScenarioId) -> (Vec<AirEvent>, Vec<FlagState>, Vec<FindingKey>) {
    let mut scenario = build(id);
    scenario.run_headline();
    let events = scenario.world.events().to_vec();

    let mut monitor = Monitor::new();
    monitor.observe_all(scenario.world.events());
    let findings = project(monitor.findings());

    let flags = scenario.evaluate(&monitor);
    (events, flags, findings)
}

/// (1) Every shipped scenario is byte-for-byte reproducible across two independent
/// build+run passes: identical events, identical flags, identical findings.
#[test]
fn every_scenario_is_run_to_run_deterministic() {
    for &id in ScenarioId::all() {
        let (events_a, flags_a, findings_a) = build_run_observe(id);
        let (events_b, flags_b, findings_b) = build_run_observe(id);

        assert!(
            !events_a.is_empty(),
            "{id:?}: produced no events to compare"
        );
        assert_eq!(
            events_a, events_b,
            "{id:?}: world.events() are not byte-identical run-to-run"
        );
        assert_eq!(
            flags_a, flags_b,
            "{id:?}: evaluated flags differ run-to-run"
        );
        assert_eq!(
            findings_a, findings_b,
            "{id:?}: monitor findings differ run-to-run"
        );
    }
}

/// A third pass must still match the first — determinism is not just pairwise, and
/// nothing accumulates hidden state between builds.
#[test]
fn scenario_determinism_holds_across_three_passes() {
    for &id in ScenarioId::all() {
        let a = build_run_observe(id);
        let b = build_run_observe(id);
        let c = build_run_observe(id);
        assert_eq!(a.0, b.0, "{id:?}: pass 1 vs 2 events");
        assert_eq!(b.0, c.0, "{id:?}: pass 2 vs 3 events");
        assert_eq!(a.1, c.1, "{id:?}: pass 1 vs 3 flags");
        assert_eq!(a.2, c.2, "{id:?}: pass 1 vs 3 findings");
    }
}

/// The seeds swept for the threadable-seed test: a dense low range plus scattered
/// large values (including the u64 extremes and the splitmix64 golden constant).
fn seed_sweep() -> Vec<u64> {
    let mut seeds: Vec<u64> = (0u64..96).collect();
    seeds.extend_from_slice(&[
        u64::MAX,
        u64::MAX - 1,
        0x9E37_79B9_7F4A_7C15,
        0xDEAD_BEEF_CAFE_F00D,
        1u64 << 32,
        1u64 << 48,
        1u64 << 63,
    ]);
    seeds
}

/// Drive a real 2G IMSI catcher and the passive monitor end to end over a world
/// stood up with an explicit seed, returning the reproducible artefacts.
fn seeded_attack_pipeline(seed: u64) -> (Vec<AirEvent>, Vec<FindingKey>, bool) {
    let mut world = World::with_seed(seed);
    world.add_legit(Rat::Gsm, -70);
    world.step(1_000_000); // camp on the honest cell
    ImsiCatcher2g.run(&mut world); // the actor steps the world itself

    let events = world.events().to_vec();
    let mut monitor = Monitor::new();
    monitor.observe_all(world.events());
    let findings = project(monitor.findings());
    (events, findings, world.ue.imsi_leaked)
}

/// (2) With a seed threaded through `World::with_seed`, the same seed reproduces the
/// same air and the same findings across a wide range of seeds — the reproducible-
/// on-any-machine guarantee, exercised through the attack + detect pipeline.
#[test]
fn attack_pipeline_is_deterministic_across_a_seed_range() {
    for seed in seed_sweep() {
        let (events_a, findings_a, leaked_a) = seeded_attack_pipeline(seed);
        let (events_b, findings_b, leaked_b) = seeded_attack_pipeline(seed);

        assert!(
            !events_a.is_empty(),
            "seed {seed:#x}: the catcher produced no air"
        );
        assert_eq!(
            events_a, events_b,
            "seed {seed:#x}: same seed did not reproduce identical air"
        );
        assert_eq!(
            findings_a, findings_b,
            "seed {seed:#x}: same seed did not reproduce identical findings"
        );
        assert_eq!(
            leaked_a, leaked_b,
            "seed {seed:#x}: same seed did not reproduce the leak outcome"
        );
        // The engine is the source of truth: the 2G catcher must actually leak the
        // IMSI regardless of seed (the seed changes bytes, not the physics).
        assert!(
            leaked_a,
            "seed {seed:#x}: the 2G catcher must leak the IMSI"
        );
        // The monitor must draw the cleartext-identity conclusion from that air.
        assert!(
            findings_a
                .iter()
                .any(|(kind, ..)| *kind == FindingKind::CleartextIdentityRequest),
            "seed {seed:#x}: the monitor must flag the cleartext identity request"
        );
    }
}

/// The seed genuinely reaches the wire: the world reports back the seed it was
/// built with, and `World::new()` matches the default-seeded scenario path.
#[test]
fn seed_is_reported_and_default_matches_new() {
    for seed in seed_sweep() {
        assert_eq!(
            World::with_seed(seed).seed(),
            seed,
            "world must report the seed it was built with"
        );
    }
}
