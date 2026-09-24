//! Drills and flag predicates for Open Cell Range.
//!
//! A [`Scenario`] builds a [`World`], names the [`Flag`]s a learner can capture,
//! and — crucially — evaluates each flag against **engine state**, not against a
//! typed answer. A flag is captured when the world actually reached the state the
//! attack was supposed to cause: the IMSI actually leaked, the UE actually camped
//! on the rogue cell, the monitor actually raised the finding. There are no
//! answer strings anywhere in this crate.
//!
//! ## The engine flow this crate implements (`site/ENGINE-API.md`)
//!
//! - `load(slug)` = [`build`] then snapshot the initial world. [`build`] stands up
//!   the **legitimate baseline** and camps the phone on it, so the "before" state
//!   is the phone on the real network — the attack has NOT run yet. The one
//!   exception is [`ScenarioId::DefendSpotTheCatcher`], whose whole point is to
//!   analyse an *already-attacked* world, so its [`build`] runs the attack too.
//! - `runAttack` = [`Scenario::run_headline`] (the scenario's headline attacker
//!   from `ocr_attack`, run against `self.world`), then observe `world.events()`
//!   with a fresh [`Monitor`] and [`Scenario::evaluate`] the flags.
//!
//! Every flag predicate reads `(&World, &Monitor)` and returns true once engine
//! state satisfies it. All of this is deterministic: the world is seeded (see
//! [`World::with_seed`]) and the attackers add no entropy of their own.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use ocr_air::{CellBehavior, Rat, World};
use ocr_attack::{
    Attacker, Downgrader, ImsiCatcher2g, ImsiCatcher4g, ImsiPager4g, LinkabilityProbe5g,
    NullCipherForcer, SuciNullExploit,
};
use ocr_detect::{FindingKind, Monitor};

/// How long [`build`] advances the world to camp the phone on the legitimate
/// baseline (one virtual second; a full camp-and-exchange fits comfortably).
const BASELINE_STEP_US: u64 = 1_000_000;

/// How long a directly driven headline attack advances the world, for the one
/// scenario ([`ScenarioId::Nr5gSuciProtects`]) that stands up its own cell rather
/// than delegating to an `ocr_attack` actor. The actors step themselves.
const HEADLINE_STEP_US: u64 = 1_000_000;

/// dBm a directly driven rogue cell adds above the strongest cell already present,
/// so it wins signal-strength selection. Mirrors `ocr_attack`'s own margin.
const DOMINATE_MARGIN_DBM: i16 = 10;

/// The signal a rogue cell needs to out-signal every cell already in the world.
/// Computed from the current cells so it works regardless of the baseline signal.
fn dominating_signal(world: &World) -> i16 {
    world
        .cells
        .iter()
        .map(|c| c.signal_dbm)
        .max()
        .unwrap_or(-90)
        .saturating_add(DOMINATE_MARGIN_DBM)
}

/// The scenarios the range ships.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScenarioId {
    /// 2G: catch an IMSI with a rogue BTS.
    Gsm2gImsiCatch,
    /// 2G: force null encryption.
    Gsm2gNullCipher,
    /// 4G: catch an IMSI before the security context exists.
    Lte4gImsiCatch,
    /// 4G: bidding-down from LTE to GSM.
    Lte4gDowngrade,
    /// 4G: confirm a specific subscriber is present by paging on the IMSI.
    Lte4gPaging,
    /// 5G: SUCI defeats the cleartext request — the fix, shown working.
    Nr5gSuciProtects,
    /// 5G: the null protection scheme undoes the fix.
    Nr5gNullScheme,
    /// 5G: the AKA failure-message linkability oracle links a challenge to a target.
    Nr5gLinkability,
    /// Defender track: run a monitor over an attacked world and raise the finding.
    DefendSpotTheCatcher,
}

impl ScenarioId {
    /// Every scenario, in teaching order.
    pub fn all() -> &'static [ScenarioId] {
        use ScenarioId::*;
        &[
            Gsm2gImsiCatch,
            Gsm2gNullCipher,
            Lte4gImsiCatch,
            Lte4gDowngrade,
            Lte4gPaging,
            Nr5gSuciProtects,
            Nr5gNullScheme,
            Nr5gLinkability,
            DefendSpotTheCatcher,
        ]
    }

    /// Stable string id for URLs, saved progress and the capture seam.
    pub fn slug(&self) -> &'static str {
        use ScenarioId::*;
        match self {
            Gsm2gImsiCatch => "gsm-2g-imsi-catch",
            Gsm2gNullCipher => "gsm-2g-null-cipher",
            Lte4gImsiCatch => "lte-4g-imsi-catch",
            Lte4gDowngrade => "lte-4g-downgrade",
            Lte4gPaging => "lte-4g-paging",
            Nr5gSuciProtects => "nr-5g-suci-protects",
            Nr5gNullScheme => "nr-5g-null-scheme",
            Nr5gLinkability => "nr-5g-linkability",
            DefendSpotTheCatcher => "defend-spot-the-catcher",
        }
    }

    /// The teaching track this scenario belongs to, for the catalogue grouping:
    /// one of `"2g" | "4g" | "5g" | "defend"` (see `site/ENGINE-API.md`).
    pub fn track(&self) -> &'static str {
        use ScenarioId::*;
        match self {
            Gsm2gImsiCatch | Gsm2gNullCipher => "2g",
            Lte4gImsiCatch | Lte4gDowngrade | Lte4gPaging => "4g",
            Nr5gSuciProtects | Nr5gNullScheme | Nr5gLinkability => "5g",
            DefendSpotTheCatcher => "defend",
        }
    }
}

/// A predicate over engine state. Returns true once the flag's condition holds.
pub type FlagPredicate = Box<dyn Fn(&World, &Monitor) -> bool>;

/// One capturable flag.
pub struct Flag {
    pub id: &'static str,
    pub title: String,
    /// Shown when a learner is stuck; never the answer, just a nudge.
    pub hint: String,
    pub predicate: FlagPredicate,
}

/// Whether a flag has been captured, for reporting to the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlagState {
    pub id: String,
    pub captured: bool,
}

/// A built drill: a starting world, a brief, and its flags.
pub struct Scenario {
    pub id: ScenarioId,
    pub title: String,
    pub brief: String,
    pub world: World,
    pub flags: Vec<Flag>,
}

impl Scenario {
    /// Run the scenario's headline attack against `self.world`.
    ///
    /// This is the `runAttack` half of the engine flow: it applies the scenario's
    /// attacker(s) from `ocr_attack` to the world, leaving it in the state the flag
    /// predicates read. **The `ocr_attack` actors step the world themselves**, so
    /// after this call the world is fully advanced; a scenario need not step again.
    ///
    /// Two arms do not delegate to an actor:
    /// - [`ScenarioId::Nr5gSuciProtects`] stands up an NR identity-catcher against
    ///   the (Profile A) network directly — there is no "catcher that fails" actor,
    ///   because the teaching point is that it *fails*: SUCI conceals the SUPI and
    ///   nothing leaks.
    /// - [`ScenarioId::DefendSpotTheCatcher`] already ran its attack in [`build`],
    ///   so this is a no-op; the world already carries the attack in its event log.
    pub fn run_headline(&mut self) {
        use ScenarioId::*;
        match self.id {
            Gsm2gImsiCatch => ImsiCatcher2g.run(&mut self.world),
            Gsm2gNullCipher => NullCipherForcer.run(&mut self.world),
            Lte4gImsiCatch => ImsiCatcher4g.run(&mut self.world),
            Lte4gDowngrade => Downgrader.run(&mut self.world),
            Lte4gPaging => ImsiPager4g.run(&mut self.world),
            Nr5gLinkability => LinkabilityProbe5g.run(&mut self.world),
            Nr5gSuciProtects => {
                // Point an NR identity-catcher at a properly configured (Profile A)
                // network. The catcher out-signals the real cell and the UE camps
                // on it, but the registration still conceals the SUPI, so the
                // catcher learns nothing — the fix, working.
                let signal = dominating_signal(&self.world);
                self.world
                    .add_rogue(Rat::Nr, signal, CellBehavior::IdentityCatcher);
                self.world.step(HEADLINE_STEP_US);
            }
            Nr5gNullScheme => SuciNullExploit.run(&mut self.world),
            // The attack already happened in `build`; re-running would only re-camp
            // a stable cell (a no-op on the event log). Nothing to do.
            DefendSpotTheCatcher => {}
        }
    }

    /// Evaluate every flag against the current world and monitor.
    pub fn evaluate(&self, monitor: &Monitor) -> Vec<FlagState> {
        self.flags
            .iter()
            .map(|f| FlagState {
                id: f.id.into(),
                captured: (f.predicate)(&self.world, monitor),
            })
            .collect()
    }
}

/// Assemble one [`Flag`]. Keeps the scenario table terse and consistent.
fn flag(id: &'static str, title: &str, hint: &str, predicate: FlagPredicate) -> Flag {
    Flag {
        id,
        title: title.into(),
        hint: hint.into(),
        predicate,
    }
}

/// Build a scenario by id, wiring its world and flag predicates.
///
/// The world is seeded deterministically (via [`World::new`]) so the same scenario
/// always produces the same air. See the crate-level docs for the load/runAttack
/// flow each scenario is built to.
pub fn build(id: ScenarioId) -> Scenario {
    use ScenarioId::*;
    let (title, brief, world, flags): (&str, &str, World, Vec<Flag>) = match id {
        Gsm2gImsiCatch => {
            let mut world = World::new();
            world.add_legit(Rat::Gsm, -70);
            world.step(BASELINE_STEP_US); // camp on the honest 2G cell first
            let flags = vec![flag(
                "imsi-recovered",
                "Recover the IMSI",
                "The phone answers an Identity Request before it trusts the cell. \
                 Which cell out-signals the real network?",
                Box::new(|w: &World, _: &Monitor| w.ue.imsi_leaked),
            )];
            (
                "Catch an IMSI on 2G",
                "Stand up a rogue cell that out-signals the network and ask the phone \
                 who it is. In 2G it just answers.",
                world,
                flags,
            )
        }
        Gsm2gNullCipher => {
            let mut world = World::new();
            world.add_legit(Rat::Gsm, -70);
            world.step(BASELINE_STEP_US);
            let flags = vec![flag(
                "null-cipher-forced",
                "Force null encryption",
                "In GSM the network chooses the cipher and the phone cannot refuse. \
                 Watch the Cipher Mode Command.",
                Box::new(|w: &World, _: &Monitor| w.ue.null_cipher_active),
            )];
            (
                "Turn off encryption",
                "The network picks the cipher. A rogue cell picks A5/0 — none.",
                world,
                flags,
            )
        }
        Lte4gImsiCatch => {
            let mut world = World::new();
            world.add_legit(Rat::Lte, -70);
            world.step(BASELINE_STEP_US);
            let flags = vec![flag(
                "imsi-leaked-lte",
                "Catch the IMSI on LTE",
                "Mutual auth protects traffic, not the very first identity exchange. \
                 Look before the Security Mode Command.",
                Box::new(|w: &World, _: &Monitor| {
                    w.ue.imsi_leaked && w.ue.camped_rat == Some(Rat::Lte)
                }),
            )];
            (
                "Catch an IMSI on LTE",
                "Mutual auth stops a fake tower serving traffic, but the IMSI still \
                 leaks before security starts.",
                world,
                flags,
            )
        }
        Lte4gDowngrade => {
            let mut world = World::new();
            world.add_legit(Rat::Lte, -70);
            world.step(BASELINE_STEP_US);
            let flags = vec![flag(
                "downgraded-to-2g",
                "Land the phone on 2G",
                "An unprotected reject on LTE can push the phone down a generation. \
                 Where does it land, and what happens there?",
                Box::new(|w: &World, _: &Monitor| {
                    w.ue.camped_rat == Some(Rat::Gsm) && w.ue.imsi_leaked
                }),
            )];
            (
                "Force a downgrade to 2G",
                "An unprotected reject pushes the phone off LTE and down to GSM, where \
                 the 2G attacks apply.",
                world,
                flags,
            )
        }
        Lte4gPaging => {
            let mut world = World::new();
            world.add_legit(Rat::Lte, -70);
            world.step(BASELINE_STEP_US);
            let flags = vec![flag(
                "presence-confirmed",
                "Confirm the target is present",
                "A network should page by a temporary id; paging by the permanent IMSI \
                 tells a listener a specific subscriber is in the cell.",
                // The presence-confirmation tell is what a Rayhunter-class monitor
                // concludes from the same air: an IMSI page. The identity content
                // never leaks — only the fact that this subscriber is here.
                Box::new(|_: &World, m: &Monitor| {
                    m.findings()
                        .iter()
                        .any(|f| f.kind == FindingKind::ImsiPaging)
                }),
            )];
            (
                "Confirm a target is nearby",
                "Page a phone by its permanent identity and watch the network give away \
                 that a specific subscriber is here — the ToRPEDO/PIERCER presence-\
                 confirmation pattern.",
                world,
                flags,
            )
        }
        Nr5gSuciProtects => {
            // Profile A is the World default; keep it, and camp on the real 5G cell.
            let mut world = World::new();
            world.add_legit(Rat::Nr, -60);
            world.step(BASELINE_STEP_US);
            let flags = vec![flag(
                "suci-holds",
                "SUCI holds",
                "Ask for the identity and read what comes back. Under Profile A it is \
                 concealed — the catcher learns nothing.",
                // The fix, working: after the catcher runs, the identity STAYED
                // protected — the SUPI never leaked.
                Box::new(|w: &World, _: &Monitor| !w.ue.imsi_leaked),
            )];
            (
                "SUCI does its job",
                "Ask a 5G phone for its identity. It answers with a SUCI you cannot \
                 read. The fix, working.",
                world,
                flags,
            )
        }
        Nr5gNullScheme => {
            let mut world = World::new();
            world.add_legit(Rat::Nr, -60);
            world.step(BASELINE_STEP_US);
            let flags = vec![flag(
                "supi-in-clear",
                "Recover the SUPI",
                "Protection Scheme 0 is spec-legal and conceals nothing. What does the \
                 registration actually carry?",
                Box::new(|w: &World, _: &Monitor| w.ue.imsi_leaked),
            )];
            (
                "Undo SUCI with the null scheme",
                "A network configured for the null protection scheme sends the SUPI in \
                 the clear anyway.",
                world,
                flags,
            )
        }
        Nr5gLinkability => {
            let mut world = World::new();
            world.add_legit(Rat::Nr, -60);
            world.step(BASELINE_STEP_US);
            let flags = vec![flag(
                "target-linked",
                "Link the challenge to its subscriber",
                "The two failure causes are distinguishable on the air — one means \
                 'not my key', the other 'my key, wrong sequence', which confirms the \
                 challenge belonged to this subscriber.",
                // SUCI conceals the identity, so nothing leaks the SUPI; the tell is
                // the AKA failure-message oracle, which the monitor raises when it
                // sees both a MAC failure and a synch failure on one RAT.
                Box::new(|_: &World, m: &Monitor| {
                    m.findings()
                        .iter()
                        .any(|f| f.kind == FindingKind::LinkabilityProbe)
                }),
            )];
            (
                "Is this challenge theirs?",
                "Replay a captured authentication challenge. How the phone rejects it — \
                 wrong key versus stale sequence number — reveals whether that challenge \
                 was hers. SUCI hides the identity; the failure message does not.",
                world,
                flags,
            )
        }
        DefendSpotTheCatcher => {
            // The defender analyses an ALREADY-attacked world: camp on the honest
            // cell, then let a 2G IMSI catcher run, so `world.events()` carries the
            // whole capture before `run_headline` is ever called.
            let mut world = World::new();
            world.add_legit(Rat::Gsm, -70);
            world.step(BASELINE_STEP_US);
            ImsiCatcher2g.run(&mut world);
            let flags = vec![flag(
                "catcher-detected",
                "Raise the finding",
                "Let the passive monitor read the whole capture. Which finding names a \
                 permanent identity sent in the clear?",
                // The one flag that reads the Monitor: a Rayhunter-class detector
                // concludes a cleartext identity request from the same air.
                Box::new(|_: &World, m: &Monitor| {
                    m.findings()
                        .iter()
                        .any(|f| f.kind == FindingKind::CleartextIdentityRequest)
                }),
            )];
            (
                "Spot the catcher",
                "Run the passive monitor over an already-attacked world and raise the \
                 finding a real detector would.",
                world,
                flags,
            )
        }
    };

    Scenario {
        id,
        title: title.into(),
        brief: brief.into(),
        world,
        flags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The engine's `runAttack` flow: run the headline, observe the whole air with
    /// a fresh monitor, and evaluate the flags. Returns the built scenario (so the
    /// world can be inspected) alongside its flag states.
    fn run_and_evaluate(id: ScenarioId) -> (Scenario, Vec<FlagState>) {
        let mut scenario = build(id);
        scenario.run_headline();
        let mut monitor = Monitor::new();
        monitor.observe_all(scenario.world.events());
        let states = scenario.evaluate(&monitor);
        (scenario, states)
    }

    /// Whether the named flag captured in a flag-state list.
    fn captured(states: &[FlagState], id: &str) -> bool {
        states
            .iter()
            .find(|s| s.id == id)
            .unwrap_or_else(|| panic!("no flag with id {id}"))
            .captured
    }

    #[test]
    fn gsm_2g_imsi_catch_recovers_the_imsi() {
        let (w, states) = run_and_evaluate(ScenarioId::Gsm2gImsiCatch);
        assert!(w.world.ue.imsi_leaked, "the 2G catcher must leak the IMSI");
        assert_eq!(w.world.ue.camped_rat, Some(Rat::Gsm));
        assert!(captured(&states, "imsi-recovered"));
    }

    #[test]
    fn gsm_2g_null_cipher_turns_encryption_off() {
        let (w, states) = run_and_evaluate(ScenarioId::Gsm2gNullCipher);
        assert!(w.world.ue.null_cipher_active, "A5/0 must be commanded");
        assert_eq!(w.world.ue.camped_rat, Some(Rat::Gsm));
        assert!(captured(&states, "null-cipher-forced"));
    }

    #[test]
    fn lte_4g_imsi_catch_leaks_before_security() {
        let (w, states) = run_and_evaluate(ScenarioId::Lte4gImsiCatch);
        assert!(w.world.ue.imsi_leaked, "LTE leaks the IMSI pre-security");
        assert_eq!(
            w.world.ue.camped_rat,
            Some(Rat::Lte),
            "the leak happens while camped on LTE"
        );
        assert!(captured(&states, "imsi-leaked-lte"));
    }

    #[test]
    fn lte_4g_downgrade_lands_on_2g_and_leaks() {
        let (w, states) = run_and_evaluate(ScenarioId::Lte4gDowngrade);
        assert_eq!(
            w.world.ue.camped_rat,
            Some(Rat::Gsm),
            "bidding-down ends on 2G"
        );
        assert!(w.world.ue.imsi_leaked, "the 2G catcher then grabs the IMSI");
        assert!(captured(&states, "downgraded-to-2g"));
    }

    #[test]
    fn nr_5g_suci_protects_does_not_leak() {
        let (w, states) = run_and_evaluate(ScenarioId::Nr5gSuciProtects);
        assert!(
            !w.world.ue.imsi_leaked,
            "Profile A SUCI must conceal the SUPI — the fix, working"
        );
        assert_eq!(w.world.ue.camped_rat, Some(Rat::Nr));
        assert!(
            captured(&states, "suci-holds"),
            "the flag captures the identity STAYING protected"
        );
    }

    #[test]
    fn nr_5g_null_scheme_recovers_the_supi() {
        let (w, states) = run_and_evaluate(ScenarioId::Nr5gNullScheme);
        assert!(
            w.world.ue.imsi_leaked,
            "the null protection scheme puts the SUPI on the air"
        );
        assert_eq!(w.world.ue.camped_rat, Some(Rat::Nr));
        assert!(captured(&states, "supi-in-clear"));
    }

    #[test]
    fn defend_spot_the_catcher_raises_the_finding() {
        // The attack already ran in `build`, so the air already carries it.
        let scenario = build(ScenarioId::DefendSpotTheCatcher);
        assert!(
            !scenario.world.events().is_empty(),
            "build must leave an already-attacked world"
        );
        assert!(
            scenario.world.ue.imsi_leaked,
            "the pre-run 2G catcher already leaked the IMSI"
        );

        let (_, states) = run_and_evaluate(ScenarioId::DefendSpotTheCatcher);
        assert!(
            captured(&states, "catcher-detected"),
            "the monitor must raise a cleartext identity request from the same air"
        );
    }

    #[test]
    fn defend_flag_actually_reads_the_monitor() {
        // With an EMPTY monitor (no events observed) the defend flag must NOT
        // capture — proving the predicate reads the Monitor argument, not the world.
        let scenario = build(ScenarioId::DefendSpotTheCatcher);
        let empty = Monitor::new();
        let states = scenario.evaluate(&empty);
        assert!(
            !captured(&states, "catcher-detected"),
            "with nothing observed there is no finding to raise"
        );
    }

    #[test]
    fn every_scenario_builds_and_has_a_valid_track() {
        for &id in ScenarioId::all() {
            // build must not panic and must produce at least one flag.
            let scenario = build(id);
            assert_eq!(scenario.id, id);
            assert!(!scenario.title.is_empty());
            assert!(!scenario.brief.is_empty());
            assert!(!scenario.flags.is_empty(), "{:?} has no flags", id);
            for f in &scenario.flags {
                assert!(!f.title.is_empty());
                assert!(!f.hint.is_empty());
            }
            // track must be one of the four catalogue groups.
            assert!(
                matches!(id.track(), "2g" | "4g" | "5g" | "defend"),
                "{:?} has an invalid track {}",
                id,
                id.track()
            );
            // slug and title round-trip is stable.
            assert!(!id.slug().is_empty());
        }
    }

    #[test]
    fn tracks_match_the_arc() {
        assert_eq!(ScenarioId::Gsm2gImsiCatch.track(), "2g");
        assert_eq!(ScenarioId::Gsm2gNullCipher.track(), "2g");
        assert_eq!(ScenarioId::Lte4gImsiCatch.track(), "4g");
        assert_eq!(ScenarioId::Lte4gDowngrade.track(), "4g");
        assert_eq!(ScenarioId::Nr5gSuciProtects.track(), "5g");
        assert_eq!(ScenarioId::Nr5gNullScheme.track(), "5g");
        assert_eq!(ScenarioId::DefendSpotTheCatcher.track(), "defend");
    }

    #[test]
    fn build_is_deterministic() {
        // Same scenario built and run twice ⇒ identical air (seeded world, no
        // entropy from the actors). Flags therefore capture identically.
        let build_run = || {
            let mut s = build(ScenarioId::Nr5gNullScheme);
            s.run_headline();
            s.world.events().to_vec()
        };
        assert_eq!(build_run(), build_run(), "same seed ⇒ identical air");
        assert!(!build_run().is_empty());
    }

    #[test]
    fn all_ids_have_unique_slugs() {
        let ids = ScenarioId::all();
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[..i] {
                assert_ne!(a.slug(), b.slug(), "duplicate slug");
            }
        }
        assert_eq!(ids.len(), 9);
    }

    #[test]
    fn new_drills_have_the_specified_slugs_and_tracks() {
        assert_eq!(ScenarioId::Lte4gPaging.slug(), "lte-4g-paging");
        assert_eq!(ScenarioId::Lte4gPaging.track(), "4g");
        assert_eq!(ScenarioId::Nr5gLinkability.slug(), "nr-5g-linkability");
        assert_eq!(ScenarioId::Nr5gLinkability.track(), "5g");
    }

    #[test]
    fn lte_4g_paging_confirms_presence() {
        let (w, states) = run_and_evaluate(ScenarioId::Lte4gPaging);
        // The phone answered the page, confirming it is in this cell.
        assert_eq!(w.world.ue.camped_rat, Some(Rat::Lte));
        // Presence, not the identity itself — the IMSI content never leaked.
        assert!(
            !w.world.ue.imsi_leaked,
            "paging confirms presence, it does not leak the identity"
        );
        // The intended finding is raised from the same air.
        let mut mon = Monitor::new();
        mon.observe_all(w.world.events());
        assert!(
            mon.findings()
                .iter()
                .any(|f| f.kind == FindingKind::ImsiPaging),
            "the monitor must flag IMSI paging"
        );
        assert!(captured(&states, "presence-confirmed"));
    }

    #[test]
    fn benign_world_does_not_confirm_presence() {
        // Control: a legitimate LTE network never pages by IMSI, so there is no
        // presence-confirmation finding to raise.
        let mut world = World::new();
        world.add_legit(Rat::Lte, -70);
        world.step(BASELINE_STEP_US);
        let mut mon = Monitor::new();
        mon.observe_all(world.events());
        assert!(
            !mon.findings()
                .iter()
                .any(|f| f.kind == FindingKind::ImsiPaging),
            "a benign world must not raise IMSI paging"
        );
    }

    #[test]
    fn nr_5g_linkability_links_the_target() {
        let (w, states) = run_and_evaluate(ScenarioId::Nr5gLinkability);
        assert_eq!(w.world.ue.camped_rat, Some(Rat::Nr));
        // SUCI conceals the SUPI — only the failure message links, not the identity.
        assert!(
            !w.world.ue.imsi_leaked,
            "SUCI conceals the SUPI; only the failure cause links the challenge"
        );
        // The intended finding is raised from the same air.
        let mut mon = Monitor::new();
        mon.observe_all(w.world.events());
        assert!(
            mon.findings()
                .iter()
                .any(|f| f.kind == FindingKind::LinkabilityProbe),
            "the monitor must flag the linkability oracle"
        );
        assert!(captured(&states, "target-linked"));
    }

    #[test]
    fn benign_world_does_not_link() {
        // Control: a legitimate NR registration produces at most one AKA failure
        // type (none here), so the linkability oracle is never flagged.
        let mut world = World::new();
        world.add_legit(Rat::Nr, -60);
        world.step(BASELINE_STEP_US);
        let mut mon = Monitor::new();
        mon.observe_all(world.events());
        assert!(
            !mon.findings()
                .iter()
                .any(|f| f.kind == FindingKind::LinkabilityProbe),
            "a benign world must not raise a linkability probe"
        );
    }
}
