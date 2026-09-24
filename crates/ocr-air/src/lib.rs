//! The virtual RF medium and state machines for Open Cell Range — the analogue
//! of Open Door Range's `odr-bus`.
//!
//! A [`World`] holds cells (legitimate and attacker-injected), a phone [`Ue`],
//! the core [`Network`], and a virtual microsecond clock. Stepping it produces
//! [`AirEvent`]s — the exact observable that both the NDJSON capture seam and
//! `ocr-detect` consume. **Detectors and drills see only `AirEvent`s, never the
//! world's ground truth**, which is what keeps detection honest.
//!
//! ## Implementer notes (stubbed; fill the bodies)
//! - Cell selection is signal-strength-driven camping/reselection — model it
//!   honestly, because "be the strongest cell" is every catcher's one lever.
//! - `step` is deterministic: no wall clock, seeded RNG only, threaded from the
//!   scenario. Same inputs, same `AirEvent` sequence, always.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use ocr_identity::Plmn;

/// Radio access technology. Mirrors the `rat` field of the NDJSON capture seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rat {
    Gsm,
    Lte,
    Nr,
}

/// Which way a message travelled. Mirrors the `dir` field of the capture seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    NetToUe,
    UeToNet,
    /// Seen by a passive third party (a monitor), direction not otherwise known.
    Observed,
}

/// An opaque cell identity as it appears on the air / in a capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CellId(pub u32);

/// A decoded message on the air, tagged by generation. This is the union the air
/// carries; the per-generation crates own the variants' internals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    Gsm(ocr_gsm::GsmMessage),
    LteNas(ocr_lte::LteNasMessage),
    LteRrc(ocr_lte::LteRrcMessage),
    NrNas(ocr_nr::NrNasMessage),
    NrRrc(ocr_nr::NrRrcMessage),
}

/// One observed message. The field set matches the NDJSON capture format in
/// `DESIGN.md` section 3 so replay and simulation are the same shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AirEvent {
    pub t_us: u64,
    pub rat: Rat,
    pub cell: CellId,
    pub dir: Direction,
    pub payload: Payload,
}

/// A cell tower in the world. `signal_dbm` is the lever selection turns on;
/// `legitimate` is ground truth the world keeps but never shows a detector.
#[derive(Clone, Debug)]
pub struct Cell {
    pub id: CellId,
    pub rat: Rat,
    pub plmn: Plmn,
    /// Higher wins during selection. A rogue cell simply sets this high.
    pub signal_dbm: i16,
    /// Ground truth, for scoring only — detectors must infer this.
    pub legitimate: bool,
    /// Tracking/location area code as this cell advertises it.
    pub area_code: u32,
}

/// UE radio capabilities — which RATs it will use and whether it will fall back.
/// The lever behind downgrade attacks.
#[derive(Clone, Debug)]
pub struct UeCapabilities {
    pub allow_gsm: bool,
    pub allow_lte: bool,
    pub allow_nr: bool,
    /// If false, the UE refuses to drop to a lower generation — the defence a
    /// drill can toggle on.
    pub allow_downgrade: bool,
}

impl Default for UeCapabilities {
    fn default() -> Self {
        Self {
            allow_gsm: true,
            allow_lte: true,
            allow_nr: true,
            allow_downgrade: true,
        }
    }
}

/// The phone. Holds its identities and which cell it is currently camped on.
///
/// `UeCapabilities`'s own `Default` is the non-trivial one (everything allowed);
/// `Ue` can therefore derive `Default` and inherit it.
#[derive(Clone, Debug, Default)]
pub struct Ue {
    pub capabilities: UeCapabilities,
    pub camped_on: Option<CellId>,
    pub camped_rat: Option<Rat>,
    /// Set once an attacker has caused the permanent identity to leak — a scoring
    /// signal, populated by the engine, read by flag predicates.
    pub imsi_leaked: bool,
    /// Set when a null cipher / null NAS algorithm was accepted.
    pub null_cipher_active: bool,
}

/// The legitimate core network side (home keys live here, in the simulation).
#[derive(Clone, Debug, Default)]
pub struct Network {
    pub home_plmn: Option<Plmn>,
}

/// A sink for observed events — the seam a passive monitor or a capture writer
/// attaches to.
pub trait Tap {
    fn on_event(&mut self, ev: &AirEvent);
}

/// The whole simulated radio world.
pub struct World {
    pub now_us: u64,
    pub cells: Vec<Cell>,
    pub ue: Ue,
    pub network: Network,
    events: Vec<AirEvent>,
}

impl World {
    /// A fresh world with a clock at zero.
    pub fn new() -> Self {
        Self {
            now_us: 0,
            cells: Vec::new(),
            ue: Ue::default(),
            network: Network::default(),
            events: Vec::new(),
        }
    }

    /// Add a cell (legitimate setup, or an attacker's rogue cell).
    pub fn add_cell(&mut self, cell: Cell) {
        self.cells.push(cell);
    }

    /// Inject a message onto the air directly (attacker actors use this).
    pub fn inject(&mut self, ev: AirEvent) {
        let _ = ev;
        unimplemented!("record + apply an injected event")
    }

    /// Advance the world by `dt_us` microseconds, running selection and any
    /// in-flight exchanges, appending to the event log.
    pub fn step(&mut self, dt_us: u64) {
        let _ = dt_us;
        unimplemented!("deterministic world step")
    }

    /// The events produced so far — the observable stream detectors read.
    pub fn events(&self) -> &[AirEvent] {
        &self.events
    }

    /// The cell the UE would select right now under signal-strength rules.
    pub fn best_cell(&self) -> Option<CellId> {
        unimplemented!("selection: strongest allowed cell")
    }
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

/// A human-readable label for an event, for the sandbox message list.
pub fn describe(ev: &AirEvent) -> String {
    let _ = ev;
    unimplemented!("one-line description of an air event")
}
