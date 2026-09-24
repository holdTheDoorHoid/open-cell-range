//! Drills and flag predicates for Open Cell Range.
//!
//! A [`Scenario`] builds a [`World`], names the [`Flag`]s a learner can capture,
//! and — crucially — evaluates each flag against **engine state**, not against a
//! typed answer. A flag is captured when the world actually reached the state the
//! attack was supposed to cause: the IMSI actually leaked, the UE actually camped
//! on the rogue cell, the monitor actually raised the finding. There are no
//! answer strings anywhere in this crate.
//!
//! ## Implementer notes (stubbed; fill the bodies)
//! - Keep the scenario catalogue data-driven; the arc is 2G → 4G → 5G plus a
//!   defender track that runs the same worlds through `ocr-detect`.
//! - Predicates read `World` and `Monitor`; they must be deterministic.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use ocr_air::World;
use ocr_detect::Monitor;

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
    /// 5G: SUCI defeats the cleartext request — the fix, shown working.
    Nr5gSuciProtects,
    /// 5G: the null protection scheme undoes the fix.
    Nr5gNullScheme,
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
            Nr5gSuciProtects,
            Nr5gNullScheme,
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
            Nr5gSuciProtects => "nr-5g-suci-protects",
            Nr5gNullScheme => "nr-5g-null-scheme",
            DefendSpotTheCatcher => "defend-spot-the-catcher",
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

/// Build a scenario by id, wiring its world and flag predicates.
pub fn build(id: ScenarioId) -> Scenario {
    let _ = id;
    unimplemented!("construct the scenario's world and flags")
}
