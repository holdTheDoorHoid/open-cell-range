//! Seed-level determinism for the virtual RF engine — the lowest layer of the
//! reproducibility guarantee in `DESIGN.md` section 3: *same scenario + same seed
//! ⇒ identical `AirEvent`s*. AKA challenges and ECIES ephemeral keys are the only
//! sources of "randomness", and they come from the seeded [`ocr_crypto::SeededRng`]
//! threaded through [`World::with_seed`]. This sweeps a wide range of seeds and
//! asserts every one reproduces its air byte-for-byte across independent runs.
//!
//! The unit tests in the crate cover a single seed and cross-seed *difference*;
//! this integration test covers run-to-run *identity* across many seeds and two
//! distinct world shapes, including the SUCI (NR / Profile A) path where the
//! ephemeral key is seed-derived.

use ocr_air::{AirEvent, CellBehavior, Rat, World};

/// Seeds swept: a dense low range plus scattered large values and the u64 extremes.
fn seed_sweep() -> Vec<u64> {
    let mut seeds: Vec<u64> = (0u64..128).collect();
    seeds.extend_from_slice(&[
        u64::MAX,
        u64::MAX - 1,
        1u64 << 32,
        1u64 << 40,
        1u64 << 63,
        0x9E37_79B9_7F4A_7C15,
        0xC0FF_EE15_0CE1_1A2B,
    ]);
    seeds
}

/// A 2G world with an honest cell and a rogue identity-catcher that out-signals it
/// — the classic catcher shape, and a path that carries a GSM auth challenge.
fn run_gsm_world(seed: u64) -> Vec<AirEvent> {
    let mut w = World::with_seed(seed);
    w.add_legit(Rat::Gsm, -80);
    w.add_rogue(Rat::Gsm, -50, CellBehavior::IdentityCatcher);
    w.step(2_000_000);
    w.events().to_vec()
}

/// A 5G world (Profile A SUCI is the `World` default) with an honest cell and a
/// rogue identity-catcher — exercises the ECIES ephemeral-key path, whose on-air
/// bytes are derived from the seed.
fn run_nr_world(seed: u64) -> Vec<AirEvent> {
    let mut w = World::with_seed(seed);
    w.add_legit(Rat::Nr, -60);
    w.add_rogue(Rat::Nr, -45, CellBehavior::IdentityCatcher);
    w.step(2_000_000);
    w.events().to_vec()
}

/// Every seed reproduces its GSM air identically across two independent runs.
#[test]
fn gsm_world_is_reproducible_across_seed_range() {
    for seed in seed_sweep() {
        let a = run_gsm_world(seed);
        let b = run_gsm_world(seed);
        assert!(!a.is_empty(), "seed {seed:#x}: no GSM air produced");
        assert_eq!(
            a, b,
            "seed {seed:#x}: GSM air is not reproducible run-to-run"
        );
    }
}

/// Every seed reproduces its NR (SUCI) air identically — the crypto-RNG path is
/// deterministic under a fixed seed.
#[test]
fn nr_world_is_reproducible_across_seed_range() {
    for seed in seed_sweep() {
        let a = run_nr_world(seed);
        let b = run_nr_world(seed);
        assert!(!a.is_empty(), "seed {seed:#x}: no NR air produced");
        assert_eq!(
            a, b,
            "seed {seed:#x}: NR air is not reproducible run-to-run"
        );
    }
}

/// `World::new()` is exactly the default-seeded world, and it too is reproducible —
/// this is the seed the drill layer's `build()` relies on.
#[test]
fn default_world_matches_a_fixed_seed_and_reproduces() {
    let default_seed = World::new().seed();
    // `new()` and `with_seed(default)` must agree, run-to-run.
    let via_new = {
        let mut w = World::new();
        w.add_legit(Rat::Lte, -70);
        w.step(1_000_000);
        w.events().to_vec()
    };
    let via_seed = {
        let mut w = World::with_seed(default_seed);
        w.add_legit(Rat::Lte, -70);
        w.step(1_000_000);
        w.events().to_vec()
    };
    assert_eq!(
        via_new, via_seed,
        "World::new() must equal World::with_seed(default_seed)"
    );
    assert!(!via_new.is_empty(), "default world produced no air");
}

/// The seed is actually threaded to the wire: at least one pair of distinct seeds
/// produces distinct NR air (the ephemeral SUCI key is seed-derived). This proves
/// the reproducibility above is not the trivial "seed is ignored" case.
#[test]
fn distinct_seeds_can_change_the_air() {
    let seeds = seed_sweep();
    let baseline = run_nr_world(seeds[0]);
    let any_different = seeds.iter().skip(1).any(|&s| run_nr_world(s) != baseline);
    assert!(
        any_different,
        "no seed changed the NR air — the seed is not reaching the wire"
    );
}
