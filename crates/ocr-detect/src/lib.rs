//! The defensive half of Open Cell Range — a passive, Rayhunter-class monitor.
//!
//! A [`Monitor`] consumes the [`AirEvent`] stream a [`World`] produces and states
//! what a real passive detector would conclude: an unexpected cell identity, a
//! location area that jumped, a downgrade when a better RAT was available, a null
//! cipher, a cleartext identity request, an authentication the network never
//! completed. It sees **only the observable stream** — never the world's
//! ground-truth `legitimate` flag — which is exactly the constraint a real
//! detector works under.
//!
//! This crate is a first-class part of the project: the point of the range is
//! that a defender runs it and learns what their own air looks like under attack.
//!
//! ## Implementer notes (stubbed; fill the bodies)
//! - Each heuristic maps to a documented real-world detection; cite it in a
//!   comment. Keep false-positive reasoning explicit — a detector that cries wolf
//!   teaches the wrong lesson.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use ocr_air::AirEvent;

/// How alarming a finding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

/// The kind of thing a monitor caught. Stable ids so the UI and drills can key on
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingKind {
    CleartextIdentityRequest,
    NullCipherCommanded,
    ForcedDowngrade,
    UnexpectedCellIdentity,
    LocationAreaJumped,
    AuthenticationNeverCompleted,
    ImplausibleSignalStrength,
    RejectStorm,
    NullSuciScheme,
}

/// One conclusion the monitor drew, with the event that triggered it.
#[derive(Clone, Debug)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    /// Microsecond timestamp of the triggering event.
    pub t_us: u64,
    /// Human-readable explanation, phrased as what a defender should think.
    pub detail: String,
}

/// A passive monitor. Feed it events; ask it for findings.
#[derive(Default)]
pub struct Monitor {
    findings: Vec<Finding>,
}

impl Monitor {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    /// Observe one event, possibly producing findings.
    pub fn observe(&mut self, ev: &AirEvent) {
        let _ = ev;
        unimplemented!("run heuristics over the event")
    }

    /// Observe a whole stream at once.
    pub fn observe_all(&mut self, events: &[AirEvent]) {
        for ev in events {
            self.observe(ev);
        }
    }

    /// Everything caught so far.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
}
