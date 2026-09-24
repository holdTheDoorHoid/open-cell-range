//! Attacker actors for Open Cell Range.
//!
//! Each actor drives a [`World`] the way a real attacker would — a rogue cell
//! that out-signals the network, a reject that forces a downgrade, a cipher-mode
//! command that turns encryption off. Actors change world state; **flags are
//! then awarded on that state**, never on the actor claiming success (see
//! `DESIGN.md`, "the rule that makes drills trustworthy").
//!
//! ## How these actors drive the world
//!
//! Every actor is built entirely on the `ocr-air` **attacker seam** — it stands up
//! rogue cells with [`CellBehavior`] profiles, sets the world SUCI scheme, and
//! steps the world. Nothing here reaches into the per-generation crates
//! (`ocr-gsm`/`ocr-lte`/`ocr-nr`) directly; the honest per-RAT exchange lives in
//! `World::step`, and an actor only chooses *which cells exist and how strong they
//! are* — because "be the strongest cell on the target's network" is every
//! catcher's one real lever (`DESIGN.md`, Track 0). A rogue cell an actor adds is
//! always placed a fixed margin above the strongest cell already in the world, so
//! the attack lands whether the caller seeded a strong or a weak legitimate
//! baseline.
//!
//! ## Contract: `run` steps the world itself
//!
//! **Each [`Attacker::run`] sets up its cells/scheme and then calls
//! `world.step(...)` before returning.** Call it once on a fresh world (typically
//! one with a legitimate cell already present). After `run`, the world is already
//! in the state its flag predicate checks — `ue.imsi_leaked`, `ue.camped_rat`,
//! `ue.null_cipher_active`, `ue.camped_on`. A scenario may safely `world.step(...)`
//! again afterward: a stable camp emits no new events, so re-stepping does not
//! change the outcome. Determinism is inherited from the world — actors introduce
//! no clock or entropy of their own.
//!
//! Nothing here is carrier-specific or a working real-world exploit; it is the
//! documented attack shape against the simulated stack. See `docs/ETHICS.md`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use ocr_air::{CellBehavior, Rat, World};
use ocr_crypto::suci::ProtectionScheme;

/// How long a single `run` advances the world, in virtual microseconds. One
/// virtual second is ample for a full camp-and-exchange; because a stable camp
/// emits nothing further, a scenario that steps again after `run` sees no change.
const STEP_US: u64 = 1_000_000;

/// dBm a rogue cell adds above the strongest cell already present, so it reliably
/// wins signal-strength selection. Selection is strongest-signal (honouring the
/// downgrade capability), so a margin over the current maximum is all a catcher
/// needs to be chosen.
const DOMINATE_MARGIN_DBM: i16 = 10;

/// The signal a rogue cell uses to out-signal every cell already in the world.
/// Computed from the world's current cells so an actor works regardless of the
/// legitimate baseline the caller seeded (and on an empty world falls back to a
/// plausible strong value).
fn dominating_signal(world: &World) -> i16 {
    world
        .cells
        .iter()
        .map(|c| c.signal_dbm)
        .max()
        .unwrap_or(-90)
        .saturating_add(DOMINATE_MARGIN_DBM)
}

/// One attack, driving a world toward the state its flag predicate checks.
pub trait Attacker {
    /// Stable identifier used by scenarios and the UI.
    fn id(&self) -> &'static str;
    /// One-line human description.
    fn describe(&self) -> &'static str;
    /// Execute the attack against the world. Implementations in this crate set up
    /// their cells/scheme and then **step the world themselves** before returning,
    /// leaving it in the state the flag predicate reads (see the crate-level
    /// "Contract" note).
    fn run(&mut self, world: &mut World);
}

/// 2G: stand up a rogue BTS on the target PLMN with a strong signal, let the UE
/// camp, then request the IMSI in cleartext.
///
/// After `run`: the UE is camped on the rogue GSM cell (`camped_rat == Gsm`) and
/// `ue.imsi_leaked` is true.
#[derive(Default)]
pub struct ImsiCatcher2g;

impl Attacker for ImsiCatcher2g {
    fn id(&self) -> &'static str {
        "imsi_catch_2g"
    }
    fn describe(&self) -> &'static str {
        "Rogue 2G cell requests the IMSI in cleartext"
    }
    fn run(&mut self, world: &mut World) {
        let signal = dominating_signal(world);
        world.add_rogue(Rat::Gsm, signal, CellBehavior::IdentityCatcher);
        world.step(STEP_US);
    }
}

/// 4G → 2G bidding-down: a rogue LTE cell that rejects, plus a rogue 2G catcher
/// the UE falls to. The unprotected reject strips the subscriber back to the
/// broken-by-design generation, where the IMSI is grabbed in cleartext.
///
/// After `run`: the UE is camped on the rogue GSM cell (`camped_rat == Gsm`) and
/// `ue.imsi_leaked` is true. The LTE rogue out-signals everything (so it is tried
/// first and rejects); the GSM rogue out-signals every legitimate cell (so the UE
/// falls to it once the LTE rogue is barred).
#[derive(Default)]
pub struct Downgrader;

impl Attacker for Downgrader {
    fn id(&self) -> &'static str {
        "downgrade_lte_to_2g"
    }
    fn describe(&self) -> &'static str {
        "Force bidding-down from LTE to GSM via unprotected reject"
    }
    fn run(&mut self, world: &mut World) {
        let base = dominating_signal(world);
        // The rogue LTE cell is the strongest, so the UE tries it first; it sends
        // an unprotected pre-auth reject and bars itself.
        world.add_rogue(
            Rat::Lte,
            base.saturating_add(DOMINATE_MARGIN_DBM),
            CellBehavior::Downgrader,
        );
        // The rogue 2G catcher still out-signals every legitimate cell, so once
        // the LTE rogue is barred the UE reselects onto it — the downgrade.
        world.add_rogue(Rat::Gsm, base, CellBehavior::IdentityCatcher);
        world.step(STEP_US);
    }
}

/// 2G: command A5/0 so traffic is unencrypted (the rogue also catches the IMSI).
///
/// After `run`: the UE is camped on the rogue GSM cell, `ue.null_cipher_active`
/// is true, and `ue.imsi_leaked` is true.
#[derive(Default)]
pub struct NullCipherForcer;

impl Attacker for NullCipherForcer {
    fn id(&self) -> &'static str {
        "force_null_cipher"
    }
    fn describe(&self) -> &'static str {
        "Command A5/0 so nothing is encrypted"
    }
    fn run(&mut self, world: &mut World) {
        let signal = dominating_signal(world);
        world.add_rogue(Rat::Gsm, signal, CellBehavior::NullCipher);
        world.step(STEP_US);
    }
}

/// LTE: catch the IMSI via the cleartext Identity Request the network sends before
/// the security context exists — the leak that survives mutual authentication. The
/// rogue eNodeB cannot then complete AKA (it holds no subscriber key), but the
/// IMSI is already on the air.
///
/// After `run`: the UE is camped on the rogue LTE cell (`camped_rat == Lte`) and
/// `ue.imsi_leaked` is true.
#[derive(Default)]
pub struct ImsiCatcher4g;

impl Attacker for ImsiCatcher4g {
    fn id(&self) -> &'static str {
        "imsi_catch_4g"
    }
    fn describe(&self) -> &'static str {
        "Rogue eNodeB requests IMSI before security is established"
    }
    fn run(&mut self, world: &mut World) {
        let signal = dominating_signal(world);
        world.add_rogue(Rat::Lte, signal, CellBehavior::IdentityCatcher);
        world.step(STEP_US);
    }
}

/// 5G: exploit a network configured for the null protection scheme, so the SUPI
/// is sent in the clear despite "SUCI being on". An attacker cannot flip a real
/// network's scheme, so setting it here models the spec-permitted / misconfigured
/// null-scheme case the SUPI leak depends on (`DESIGN.md`, Track 3); the rogue NR
/// cell then captures the registration whose SUCI is really the plaintext SUPI.
///
/// After `run`: the world SUCI scheme is [`ProtectionScheme::Null`], the UE is
/// camped on the rogue NR cell (`camped_rat == Nr`), and `ue.imsi_leaked` is true
/// (the SUPI was recovered by a passive observer).
#[derive(Default)]
pub struct SuciNullExploit;

impl Attacker for SuciNullExploit {
    fn id(&self) -> &'static str {
        "suci_null_scheme"
    }
    fn describe(&self) -> &'static str {
        "Recover SUPI when the null protection scheme is configured"
    }
    fn run(&mut self, world: &mut World) {
        // The 5G "fix" configured off: the null scheme puts the SUPI on the air.
        world.set_suci_scheme(ProtectionScheme::Null);
        let signal = dominating_signal(world);
        world.add_rogue(Rat::Nr, signal, CellBehavior::IdentityCatcher);
        world.step(STEP_US);
    }
}

/// Every actor the range ships, in 2G → 4G → 5G teaching order, for the sandbox
/// picker and the scenario loader.
pub fn all() -> Vec<Box<dyn Attacker>> {
    vec![
        Box::new(ImsiCatcher2g),
        Box::new(NullCipherForcer),
        Box::new(ImsiCatcher4g),
        Box::new(Downgrader),
        Box::new(SuciNullExploit),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ocr_air::{CellId, World};

    /// True if the UE is camped on a cell whose ground-truth `legitimate` flag is
    /// false — i.e. it fell for the rogue, not a real cell. (Tests may read ground
    /// truth; detectors may not.)
    fn camped_on_rogue(w: &World) -> bool {
        match w.ue.camped_on {
            Some(id) => cell(w, id).map(|c| !c.legitimate).unwrap_or(false),
            None => false,
        }
    }

    fn cell(w: &World, id: CellId) -> Option<&ocr_air::Cell> {
        w.cells.iter().find(|c| c.id == id)
    }

    #[test]
    fn imsi_catcher_2g_leaks_and_camps_on_rogue() {
        let mut w = World::new();
        // A legitimate cell is already serving the UE.
        w.add_legit(Rat::Lte, -60);
        ImsiCatcher2g.run(&mut w);

        assert!(w.ue.imsi_leaked, "the 2G catcher must leak the IMSI");
        assert_eq!(w.ue.camped_rat, Some(Rat::Gsm));
        assert!(
            camped_on_rogue(&w),
            "the UE must camp on the rogue, not the legit cell"
        );
    }

    #[test]
    fn null_cipher_forcer_sets_null_and_leaks() {
        let mut w = World::new();
        w.add_legit(Rat::Gsm, -60);
        NullCipherForcer.run(&mut w);

        assert!(w.ue.null_cipher_active, "A5/0 must be commanded");
        assert!(
            w.ue.imsi_leaked,
            "the null-cipher rogue also catches the IMSI"
        );
        assert_eq!(w.ue.camped_rat, Some(Rat::Gsm));
        assert!(camped_on_rogue(&w));
    }

    #[test]
    fn imsi_catcher_4g_leaks_pre_security() {
        let mut w = World::new();
        w.add_legit(Rat::Lte, -60);
        ImsiCatcher4g.run(&mut w);

        assert!(
            w.ue.imsi_leaked,
            "LTE leaks the IMSI before security exists"
        );
        assert_eq!(w.ue.camped_rat, Some(Rat::Lte));
        assert!(camped_on_rogue(&w));
        // The rogue could not complete authentication — the keyless-cell tell.
        assert!(w.events().iter().any(|e| matches!(
            &e.payload,
            ocr_air::Payload::LteNas(ocr_lte::LteNasMessage::AuthenticationFailureMacFailure)
        )));
    }

    #[test]
    fn downgrader_ends_on_gsm_and_leaks() {
        let mut w = World::new();
        // A legitimate LTE cell the UE would happily stay on, absent the attack.
        w.add_legit(Rat::Lte, -70);
        Downgrader.run(&mut w);

        assert_eq!(w.ue.camped_rat, Some(Rat::Gsm), "bidding-down ends on 2G");
        assert!(w.ue.imsi_leaked, "the 2G catcher then grabs the IMSI");
        assert!(camped_on_rogue(&w));
        // The unprotected reject that drove the downgrade is on the air.
        assert!(w.events().iter().any(|e| matches!(
            &e.payload,
            ocr_air::Payload::LteRrc(ocr_lte::LteRrcMessage::ConnectionReject { .. })
        )));
    }

    #[test]
    fn downgrade_defence_defeats_the_downgrader() {
        // With downgrade disallowed, the UE refuses to fall from LTE to 2G, so the
        // attack lands nothing — the defensive lesson the same actor teaches.
        let mut w = World::new();
        w.ue.capabilities.allow_downgrade = false;
        w.add_legit(Rat::Lte, -70);
        Downgrader.run(&mut w);

        assert_ne!(w.ue.camped_rat, Some(Rat::Gsm));
        assert!(!w.ue.imsi_leaked);
    }

    #[test]
    fn suci_null_exploit_recovers_supi() {
        let mut w = World::new();
        w.add_legit(Rat::Nr, -60);
        SuciNullExploit.run(&mut w);

        assert_eq!(
            w.suci_scheme(),
            ProtectionScheme::Null,
            "the fix is set to off"
        );
        assert!(w.ue.imsi_leaked, "the null-scheme SUCI hands over the SUPI");
        assert_eq!(w.ue.camped_rat, Some(Rat::Nr));
        assert!(camped_on_rogue(&w));
    }

    #[test]
    fn profile_a_scheme_would_not_leak_supi() {
        // Control: without the null-scheme step, an NR registration conceals the
        // SUPI — confirming the leak in the test above comes from the scheme, not
        // from merely standing up a cell.
        let mut w = World::new();
        w.add_rogue(Rat::Nr, -40, CellBehavior::IdentityCatcher);
        w.step(STEP_US);
        assert!(!w.ue.imsi_leaked, "Profile A SUCI conceals the SUPI");
    }

    #[test]
    fn all_lists_every_actor_with_unique_ids() {
        let actors = all();
        assert_eq!(actors.len(), 5);
        let ids: Vec<&str> = actors.iter().map(|a| a.id()).collect();
        assert!(ids.contains(&"imsi_catch_2g"));
        assert!(ids.contains(&"force_null_cipher"));
        assert!(ids.contains(&"imsi_catch_4g"));
        assert!(ids.contains(&"downgrade_lte_to_2g"));
        assert!(ids.contains(&"suci_null_scheme"));
        // ids are unique
        for (i, a) in ids.iter().enumerate() {
            assert!(!ids[..i].contains(a), "duplicate actor id {a}");
        }
        // every actor has a non-empty description
        for a in &actors {
            assert!(!a.describe().is_empty());
        }
    }

    #[test]
    fn same_seed_produces_identical_events() {
        // Actors add no entropy of their own; the world's seed alone fixes the air.
        let build = || {
            let mut w = World::with_seed(0xA11C_5EED);
            w.add_legit(Rat::Nr, -60);
            // SuciNullExploit exercises the RNG heavily (SUCI conceal + 5G-AKA).
            SuciNullExploit.run(&mut w);
            w
        };
        let a = build();
        let b = build();
        assert_eq!(a.events(), b.events(), "same seed ⇒ identical air");
        assert!(!a.events().is_empty());
    }

    // ---- attack ↔ detection pairing (via the ocr-detect dev-dependency) --------

    #[test]
    fn monitor_catches_the_2g_imsi_catcher() {
        use ocr_detect::{FindingKind, Monitor};

        let mut w = World::new();
        w.add_legit(Rat::Lte, -60);
        ImsiCatcher2g.run(&mut w);

        let mut mon = Monitor::new();
        mon.observe_all(w.events());
        assert!(
            mon.findings()
                .iter()
                .any(|f| f.kind == FindingKind::CleartextIdentityRequest),
            "a passive monitor must flag the cleartext identity request"
        );
    }

    #[test]
    fn monitor_catches_the_null_cipher() {
        use ocr_detect::{FindingKind, Monitor};

        let mut w = World::new();
        w.add_legit(Rat::Gsm, -60);
        NullCipherForcer.run(&mut w);

        let mut mon = Monitor::new();
        mon.observe_all(w.events());
        assert!(
            mon.findings()
                .iter()
                .any(|f| f.kind == FindingKind::NullCipherCommanded),
            "a passive monitor must flag the null cipher command"
        );
    }

    #[test]
    fn monitor_catches_the_null_suci_scheme() {
        use ocr_detect::{FindingKind, Monitor};

        let mut w = World::new();
        w.add_legit(Rat::Nr, -60);
        SuciNullExploit.run(&mut w);

        let mut mon = Monitor::new();
        mon.observe_all(w.events());
        assert!(
            mon.findings()
                .iter()
                .any(|f| f.kind == FindingKind::NullSuciScheme),
            "a passive monitor must flag the null-scheme SUCI"
        );
    }
}
