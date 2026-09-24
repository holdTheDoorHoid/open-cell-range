//! The virtual RF medium and state machines for Open Cell Range — the analogue
//! of Open Door Range's `odr-bus`.
//!
//! A [`World`] holds cells (legitimate and attacker-injected), a phone [`Ue`],
//! the core [`Network`], a virtual microsecond clock, a seeded RNG, and the
//! simulated subscriber (IMSI/SUPI, the published 3GPP test-vector K/OPc, and a
//! home SUCI keypair). Stepping it produces [`AirEvent`]s — the exact observable
//! that both the NDJSON capture seam and `ocr-detect` consume. **Detectors and
//! drills see only `AirEvent`s and the [`Ue`] scoring state, never the world's
//! `Cell::legitimate` ground truth**, which is what keeps detection honest.
//!
//! Cell selection is signal-strength-driven camping/reselection — modelled
//! honestly, because "be the strongest cell" is every catcher's one lever. Every
//! step is deterministic: the clock is virtual and randomness comes only from the
//! seeded [`ocr_crypto::SeededRng`]. Same scenario + seed ⇒ identical `AirEvent`
//! sequence, always.
//!
//! # ATTACKER SEAM
//!
//! `ocr-attack` is built entirely on the surface below; it never reaches into the
//! per-generation crates directly. The seam has two layers.
//!
//! ## 1. Stand up cells with a behaviour profile
//!
//! Every [`Cell`] carries a [`CellBehavior`] that [`World::step`] runs when the UE
//! camps on it. A legitimate cell runs the honest exchange for its RAT (mutual
//! auth where the RAT supports it, a real cipher, a concealed SUCI); the other
//! profiles are the attacks:
//!
//! - [`CellBehavior::IdentityCatcher`] — requests the permanent identity before a
//!   security context exists. 2G/4G leak the IMSI in cleartext; a 5G cell only
//!   wins if the network is on the null SUCI scheme (see below).
//! - [`CellBehavior::NullCipher`] — also catches the identity, and commands null
//!   encryption (2G A5/0, LTE EEA0/EIA0, NR NEA0/NIA0), setting
//!   [`Ue::null_cipher_active`].
//! - [`CellBehavior::Downgrader`] — sends an unprotected pre-auth reject so the UE
//!   reselects away; with a lower-RAT catcher present and downgrade allowed, that
//!   is bidding-down.
//!
//! The ergonomic constructors an attacker uses:
//!
//! ```ignore
//! // Rogue 2G catcher: spoof the target PLMN, out-signal the real cell, camp, leak.
//! let rogue = world.add_rogue(Rat::Gsm, -40, CellBehavior::IdentityCatcher);
//! world.step(1_000_000);
//! assert!(world.ue.imsi_leaked);
//! assert_eq!(world.ue.camped_on, Some(rogue));
//!
//! // LTE -> 2G downgrade: reject on LTE, catch on the 2G cell the UE falls to.
//! world.add_rogue(Rat::Lte, -35, CellBehavior::Downgrader);
//! world.add_rogue(Rat::Gsm, -45, CellBehavior::IdentityCatcher);
//! world.step(1_000_000);
//! assert_eq!(world.ue.camped_rat, Some(Rat::Gsm));
//!
//! // 5G null scheme: turn the fix off, then any registration exposes the SUPI.
//! world.set_suci_scheme(ocr_crypto::suci::ProtectionScheme::Null);
//! world.add_rogue(Rat::Nr, -40, CellBehavior::IdentityCatcher);
//! world.step(1_000_000);
//! assert!(world.ue.imsi_leaked);
//! ```
//!
//! [`Cell::rogue`] / [`Cell::legit`] build a cell directly, and [`World::add_cell`]
//! takes one already built, for an attacker that wants full control of the id,
//! PLMN, signal, or advertised area code.
//!
//! ## 2. Inject raw messages
//!
//! [`World::inject`] puts a single decoded message on the air, records it in the
//! event log, and applies its scoring effect (a cleartext identity response marks
//! the IMSI leaked; a null cipher / null NAS command marks null encryption; a
//! null-scheme SUCI marks the SUPI recovered). It is the escape hatch for an
//! attack that wants to place one message without running a whole cell exchange.
//!
//! The SUCI protection scheme is a network/subscriber configuration on the world
//! ([`World::set_suci_scheme`]), not a cell property: the 5G "fix" is a toggle,
//! and turning it to [`ocr_crypto::suci::ProtectionScheme::Null`] is what makes
//! even an honest registration hand the SUPI to a passive observer.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use ocr_crypto::suci::{HomeNetworkKeyPair, ProtectionScheme};
use ocr_crypto::SeededRng;
use ocr_identity::{Guti, Imsi, Plmn, Suci, Supi, Tmsi};

/// Radio access technology. Mirrors the `rat` field of the NDJSON capture seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rat {
    Gsm,
    Lte,
    Nr,
}

impl Rat {
    /// Generation rank, high wins. Selection uses it for the downgrade rule: a
    /// higher-rank cell is a "better RAT" a defended UE refuses to drop below.
    fn rank(self) -> u8 {
        match self {
            Rat::Nr => 3,
            Rat::Lte => 2,
            Rat::Gsm => 1,
        }
    }
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

/// What a cell does when the UE camps on it. The heart of the attacker seam:
/// `World::step` dispatches the camped cell's exchange on this. See the crate-level
/// `ATTACKER SEAM` block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellBehavior {
    /// A legitimate network cell: the honest exchange for its RAT. No cleartext
    /// identity, a real cipher, a concealed SUCI.
    Legit,
    /// Requests the permanent identity before any security context exists (2G/4G
    /// cleartext IMSI; 5G only when the null SUCI scheme is configured).
    IdentityCatcher,
    /// Catches the identity and commands null encryption for its RAT.
    NullCipher,
    /// Sends an unprotected pre-auth reject to push the UE off this cell — the
    /// bidding-down lever.
    Downgrader,
}

/// A cell tower in the world. `signal_dbm` is the lever selection turns on;
/// `legitimate` is ground truth the world keeps but never shows a detector;
/// `behavior` is what [`World::step`] runs when the UE camps here.
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
    /// The exchange this cell runs. Defaults to [`CellBehavior::Legit`].
    pub behavior: CellBehavior,
}

/// Location/tracking area a legitimate cell advertises in this simulation.
const LEGIT_AREA: u32 = 1;
/// A rogue cell advertises a different area — the LAC/TAC jump a detector keys on.
const ROGUE_AREA: u32 = 0xA11C;

impl Cell {
    /// A legitimate cell of `rat` on `plmn` at `signal_dbm`.
    pub fn legit(id: CellId, rat: Rat, plmn: Plmn, signal_dbm: i16) -> Self {
        Self {
            id,
            rat,
            plmn,
            signal_dbm,
            legitimate: true,
            area_code: LEGIT_AREA,
            behavior: CellBehavior::Legit,
        }
    }

    /// A rogue cell running `behavior`. It advertises a distinct area code, the
    /// LAC/TAC jump a passive monitor can catch.
    pub fn rogue(
        id: CellId,
        rat: Rat,
        plmn: Plmn,
        signal_dbm: i16,
        behavior: CellBehavior,
    ) -> Self {
        Self {
            id,
            rat,
            plmn,
            signal_dbm,
            legitimate: false,
            area_code: ROGUE_AREA,
            behavior,
        }
    }
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

// ---- simulated subscriber (published 3GPP test vectors, never real keys) ----

/// Subscriber key K — 3GPP TS 35.208 MILENAGE test set 1. A published test
/// vector; see `docs/ETHICS.md`.
const SUBSCRIBER_K: [u8; 16] = [
    0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc,
];
/// Derived operator constant OPc for [`SUBSCRIBER_K`] — TS 35.208 test set 1.
const SUBSCRIBER_OPC: [u8; 16] = [
    0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e, 0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf,
];
/// A key the attacker does NOT hold, used to build a rogue AKA challenge the UE
/// rejects — the "authentication the network could not complete" signal.
const WRONG_K: [u8; 16] = [0u8; 16];

/// Default seed for [`World::new`]; [`World::with_seed`] overrides it.
const DEFAULT_SEED: u64 = 0x0CE1_1A6E_5EED_0001;
/// Per-message clock advance inside a step, microseconds.
const MSG_DT_US: u64 = 1_000;
/// The network's starting sequence number for AKA; kept ahead of the UE's.
const INITIAL_SQN: u64 = 0x20;
/// How far the network advances SQN per successful authentication.
const SQN_STEP: u64 = 0x20;
/// Standard AMF (authentication management field) for the AKA vectors.
const AMF: [u8; 2] = [0x80, 0x00];

/// Pack the low 48 bits of a counter into the 6-octet SQN field (big-endian).
fn sqn6(n: u64) -> [u8; 6] {
    let b = n.to_be_bytes();
    [b[2], b[3], b[4], b[5], b[6], b[7]]
}

/// Outcome of running a cell's exchange: did the UE end up camped, or was it
/// rejected (so selection bars the cell and reselects)?
enum Camp {
    Camped,
    Rejected,
}

/// The whole simulated radio world.
pub struct World {
    pub now_us: u64,
    pub cells: Vec<Cell>,
    pub ue: Ue,
    pub network: Network,
    /// The subscriber's permanent 2G/4G identity (test identity, MCC 001/MNC 01).
    pub imsi: Imsi,
    /// The subscriber's 5G permanent identity (same PLMN + MSIN as [`World::imsi`]).
    pub supi: Supi,

    k: [u8; 16],
    op_c: [u8; 16],
    home: HomeNetworkKeyPair,
    suci_scheme: ProtectionScheme,
    rng: SeededRng,
    seed: u64,
    net_sqn: u64,
    /// Cells the UE has been rejected from and will not reselect this scenario.
    barred: Vec<CellId>,
    next_id: u32,
    events: Vec<AirEvent>,
}

impl World {
    /// A fresh world with a clock at zero and the default seed.
    pub fn new() -> Self {
        Self::with_seed(DEFAULT_SEED)
    }

    /// A fresh world seeded explicitly. Same seed + same cells + same steps ⇒
    /// identical [`World::events`], always.
    pub fn with_seed(seed: u64) -> Self {
        let mut rng = SeededRng::new(seed);
        // The home network keypair is derived from the seed so a scenario's home
        // network is stable across runs.
        let home = HomeNetworkKeyPair::generate(&mut rng);
        let plmn = Plmn::new(1, 1, 2);
        let msin = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let imsi = Imsi {
            plmn,
            msin: msin.clone(),
        };
        let supi = Supi { plmn, msin };
        Self {
            now_us: 0,
            cells: Vec::new(),
            ue: Ue::default(),
            network: Network {
                home_plmn: Some(plmn),
            },
            imsi,
            supi,
            k: SUBSCRIBER_K,
            op_c: SUBSCRIBER_OPC,
            home,
            suci_scheme: ProtectionScheme::ProfileA,
            rng,
            seed,
            net_sqn: INITIAL_SQN,
            barred: Vec::new(),
            next_id: 1,
            events: Vec::new(),
        }
    }

    /// The seed this world was built with — for reproducibility reporting.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// The SUCI protection scheme the (simulated) network/subscriber is using.
    pub fn suci_scheme(&self) -> ProtectionScheme {
        self.suci_scheme
    }

    /// Set the SUCI protection scheme. Turning it to
    /// [`ProtectionScheme::Null`] is the 5G "fix configured off": even an honest
    /// registration then exposes the SUPI to a passive observer.
    pub fn set_suci_scheme(&mut self, scheme: ProtectionScheme) {
        self.suci_scheme = scheme;
    }

    /// Reserve and return the next free cell id.
    pub fn next_cell_id(&mut self) -> CellId {
        let id = CellId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Add a cell (legitimate setup, or an attacker's rogue cell).
    pub fn add_cell(&mut self, cell: Cell) {
        self.next_id = self.next_id.max(cell.id.0 + 1);
        self.cells.push(cell);
    }

    /// Attacker convenience: stand up a rogue cell of `rat` running `behavior`,
    /// spoofing the home PLMN at `signal_dbm`. Returns its id.
    pub fn add_rogue(&mut self, rat: Rat, signal_dbm: i16, behavior: CellBehavior) -> CellId {
        let plmn = self.spoof_plmn();
        let id = self.next_cell_id();
        self.add_cell(Cell::rogue(id, rat, plmn, signal_dbm, behavior));
        id
    }

    /// Convenience: add a legitimate cell of `rat` on the home PLMN. Returns its id.
    pub fn add_legit(&mut self, rat: Rat, signal_dbm: i16) -> CellId {
        let plmn = self.spoof_plmn();
        let id = self.next_cell_id();
        self.add_cell(Cell::legit(id, rat, plmn, signal_dbm));
        id
    }

    /// The PLMN a cell advertises by default — the subscriber's home network.
    fn spoof_plmn(&self) -> Plmn {
        self.network.home_plmn.unwrap_or(self.imsi.plmn)
    }

    /// Inject a decoded message onto the air directly: record it and apply its
    /// scoring effect. The raw-injection half of the attacker seam.
    pub fn inject(&mut self, ev: AirEvent) {
        self.now_us = self.now_us.max(ev.t_us);
        self.apply_effect(&ev);
        self.events.push(ev);
    }

    /// Advance the world by `dt_us` microseconds: run signal-strength selection,
    /// then the camped cell's exchange, appending to the event log. A rejecting
    /// cell bars itself and the UE reselects within the same step, so a single
    /// step can express an LTE reject that drops the UE to a 2G catcher.
    pub fn step(&mut self, dt_us: u64) {
        let start = self.now_us;
        // Bounded reselection: at most one attempt per cell, plus one.
        for _ in 0..self.cells.len() + 1 {
            match self.select() {
                None => {
                    self.ue.camped_on = None;
                    self.ue.camped_rat = None;
                    break;
                }
                Some(cid) => {
                    if self.ue.camped_on == Some(cid) {
                        // Already camped here from a previous step: nothing new.
                        break;
                    }
                    let (rat, behavior) = {
                        let c = self.cell(cid);
                        (c.rat, c.behavior)
                    };
                    match self.run_exchange(cid, rat, behavior) {
                        Camp::Camped => {
                            self.ue.camped_on = Some(cid);
                            self.ue.camped_rat = Some(rat);
                            break;
                        }
                        Camp::Rejected => {
                            self.barred.push(cid);
                            // loop to reselect the next-best cell
                        }
                    }
                }
            }
        }
        self.now_us = start.saturating_add(dt_us).max(self.now_us);
    }

    /// The events produced so far — the observable stream detectors read.
    pub fn events(&self) -> &[AirEvent] {
        &self.events
    }

    /// The cell the UE would select right now under signal-strength rules
    /// (strongest allowed, non-barred, honouring the downgrade capability).
    pub fn best_cell(&self) -> Option<CellId> {
        self.select()
    }

    // ---- selection ---------------------------------------------------------

    fn rat_allowed(&self, r: Rat) -> bool {
        match r {
            Rat::Gsm => self.ue.capabilities.allow_gsm,
            Rat::Lte => self.ue.capabilities.allow_lte,
            Rat::Nr => self.ue.capabilities.allow_nr,
        }
    }

    /// Strongest capability-allowed, non-barred cell, honouring the downgrade
    /// rule: when downgrade is disallowed the UE will not camp on a RAT below the
    /// best RAT it could otherwise use (computed over all allowed cells, barred
    /// included, so a barred LTE cell still forbids dropping to 2G).
    fn select(&self) -> Option<CellId> {
        let best_rank = self
            .cells
            .iter()
            .filter(|c| self.rat_allowed(c.rat))
            .map(|c| c.rat.rank())
            .max()?;

        let mut best: Option<&Cell> = None;
        for c in &self.cells {
            if !self.rat_allowed(c.rat) || self.barred.contains(&c.id) {
                continue;
            }
            if !self.ue.capabilities.allow_downgrade && c.rat.rank() < best_rank {
                continue;
            }
            let better = match best {
                None => true,
                Some(b) => {
                    c.signal_dbm > b.signal_dbm || (c.signal_dbm == b.signal_dbm && c.id.0 < b.id.0)
                }
            };
            if better {
                best = Some(c);
            }
        }
        best.map(|c| c.id)
    }

    fn cell(&self, id: CellId) -> &Cell {
        self.cells
            .iter()
            .find(|c| c.id == id)
            .expect("selected cell exists")
    }

    // ---- exchanges ---------------------------------------------------------

    fn emit(&mut self, rat: Rat, cell: CellId, dir: Direction, payload: Payload) {
        self.events.push(AirEvent {
            t_us: self.now_us,
            rat,
            cell,
            dir,
            payload,
        });
        self.now_us += MSG_DT_US;
    }

    fn run_exchange(&mut self, cid: CellId, rat: Rat, behavior: CellBehavior) -> Camp {
        let (plmn, area, idnum) = {
            let c = self.cell(cid);
            (c.plmn, c.area_code, c.id.0)
        };
        match rat {
            Rat::Gsm => self.gsm_exchange(cid, plmn, area as u16, idnum as u16, behavior),
            Rat::Lte => self.lte_exchange(cid, plmn, area as u16, idnum, behavior),
            Rat::Nr => self.nr_exchange(cid, plmn, area, idnum as u64, behavior),
        }
    }

    fn guti(&self) -> Guti {
        Guti {
            plmn: self.spoof_plmn(),
            mme_group_id: 1,
            mme_code: 1,
            m_tmsi: 0x0200_0000,
        }
    }

    fn gsm_exchange(
        &mut self,
        cid: CellId,
        plmn: Plmn,
        lac: u16,
        cell_id: u16,
        behavior: CellBehavior,
    ) -> Camp {
        use ocr_gsm::{Bts, GsmMessage, MobileStation, A5};

        if behavior == CellBehavior::Downgrader {
            // A 2G cell that only pushes the UE away: broadcast, then reject.
            self.emit(
                Rat::Gsm,
                cid,
                Direction::NetToUe,
                Payload::Gsm(GsmMessage::SystemInformation { plmn, lac, cell_id }),
            );
            self.emit(
                Rat::Gsm,
                cid,
                Direction::UeToNet,
                Payload::Gsm(GsmMessage::LocationUpdateRequest { tmsi: None }),
            );
            self.emit(
                Rat::Gsm,
                cid,
                Direction::NetToUe,
                Payload::Gsm(GsmMessage::LocationUpdateReject { cause: 0x0F }),
            );
            return Camp::Rejected;
        }

        let mut bts = Bts {
            plmn_configured: Some(plmn),
            lac,
            cell_id,
            ..Default::default()
        };
        let mut ms = MobileStation {
            imsi: Some(self.imsi.clone()),
            ..Default::default()
        };

        match behavior {
            CellBehavior::Legit => {
                // Established context: the network already knows the subscriber,
                // so it authenticates (with a real triplet), uses a real cipher,
                // and never asks for the IMSI. Nothing permanent hits the air.
                let mut rand = [0u8; 16];
                self.rng.fill_bytes(&mut rand);
                bts.request_imsi = false;
                bts.commanded_cipher = A5::A5_1;
                bts.auth = Some(ocr_gsm::auth_vector(&self.k, &self.op_c, &rand));
                bts.assign_tmsi = Some(Tmsi(0x0100_0000 | cid.0));
                ms.tmsi = Some(Tmsi(0x00FF_0000 | cid.0));
                ms.k = Some(self.k);
                ms.op_c = Some(self.op_c);
            }
            CellBehavior::IdentityCatcher => {
                // Request the IMSI before any auth, hold no keys, never challenge.
                bts.request_imsi = true;
                bts.commanded_cipher = A5::A5_1;
                bts.auth = None;
            }
            CellBehavior::NullCipher => {
                bts.request_imsi = true;
                bts.commanded_cipher = A5::A5_0;
                bts.auth = None;
            }
            CellBehavior::Downgrader => unreachable!("handled above"),
        }

        self.drive_gsm(cid, &mut bts, &mut ms);
        if bts.cipher == Some(A5::A5_0) {
            self.ue.null_cipher_active = true;
        }
        Camp::Camped
    }

    /// Ping-pong the GSM state machines, emitting each message in order. A
    /// cleartext IMSI in an uplink `IdentityResponse` marks the identity leaked.
    fn drive_gsm(&mut self, cid: CellId, bts: &mut ocr_gsm::Bts, ms: &mut ocr_gsm::MobileStation) {
        use ocr_gsm::GsmMessage;
        let mut downlink = vec![bts.broadcast()];
        for _ in 0..16 {
            if downlink.is_empty() {
                break;
            }
            let mut uplink = Vec::new();
            for m in &downlink {
                self.emit(Rat::Gsm, cid, Direction::NetToUe, Payload::Gsm(m.clone()));
                uplink.extend(ms.on_downlink(m));
            }
            if uplink.is_empty() {
                break;
            }
            let mut next = Vec::new();
            for m in &uplink {
                if let GsmMessage::IdentityResponse { imsi: Some(_) } = m {
                    self.ue.imsi_leaked = true;
                }
                self.emit(Rat::Gsm, cid, Direction::UeToNet, Payload::Gsm(m.clone()));
                next.extend(bts.on_uplink(m));
            }
            downlink = next;
        }
    }

    fn lte_exchange(
        &mut self,
        cid: CellId,
        plmn: Plmn,
        tac: u16,
        cell_id: u32,
        behavior: CellBehavior,
    ) -> Camp {
        use ocr_lte::{
            eps_aka_vector, pre_security_identity_exchange, ue_verify_challenge, LteNasMessage,
            LteRrcMessage, NasAlgorithm, UeSqnState,
        };

        self.emit(
            Rat::Lte,
            cid,
            Direction::NetToUe,
            Payload::LteRrc(LteRrcMessage::SystemInformation { plmn, tac, cell_id }),
        );

        if behavior == CellBehavior::Downgrader {
            // Unprotected pre-auth RRC reject — the bidding-down lever.
            self.emit(
                Rat::Lte,
                cid,
                Direction::UeToNet,
                Payload::LteRrc(LteRrcMessage::ConnectionRequest),
            );
            self.emit(
                Rat::Lte,
                cid,
                Direction::NetToUe,
                Payload::LteRrc(LteRrcMessage::ConnectionReject { wait_time: 16 }),
            );
            return Camp::Rejected;
        }

        self.emit(
            Rat::Lte,
            cid,
            Direction::UeToNet,
            Payload::LteRrc(LteRrcMessage::ConnectionRequest),
        );
        self.emit(
            Rat::Lte,
            cid,
            Direction::NetToUe,
            Payload::LteRrc(LteRrcMessage::ConnectionSetup),
        );

        if behavior == CellBehavior::Legit {
            // UE presents a valid GUTI, so no identity request is needed, then
            // EPS-AKA runs to completion under a real key and a real cipher.
            self.emit(
                Rat::Lte,
                cid,
                Direction::UeToNet,
                Payload::LteNas(LteNasMessage::AttachRequest {
                    guti: Some(self.guti()),
                }),
            );
            let mut rand = [0u8; 16];
            self.rng.fill_bytes(&mut rand);
            let sqn = sqn6(self.net_sqn);
            let v = eps_aka_vector(&self.k, &self.op_c, &rand, &sqn, &AMF, &plmn);
            self.emit(
                Rat::Lte,
                cid,
                Direction::NetToUe,
                Payload::LteNas(LteNasMessage::AuthenticationRequest {
                    rand: v.rand,
                    autn: v.autn,
                }),
            );
            let mut state = UeSqnState::new(self.net_sqn.saturating_sub(1));
            let outcome =
                ue_verify_challenge(&self.k, &self.op_c, &mut state, &v.rand, &v.autn, &plmn);
            self.emit(
                Rat::Lte,
                cid,
                Direction::UeToNet,
                Payload::LteNas(outcome.to_nas()),
            );
            self.net_sqn += SQN_STEP;
            self.emit(
                Rat::Lte,
                cid,
                Direction::NetToUe,
                Payload::LteNas(LteNasMessage::SecurityModeCommand {
                    algorithm: NasAlgorithm::EEA2_EIA2,
                }),
            );
            self.emit(
                Rat::Lte,
                cid,
                Direction::UeToNet,
                Payload::LteNas(LteNasMessage::SecurityModeComplete),
            );
            self.emit(
                Rat::Lte,
                cid,
                Direction::NetToUe,
                Payload::LteNas(LteNasMessage::AttachAccept {
                    guti: Some(self.guti()),
                }),
            );
            return Camp::Camped;
        }

        // IdentityCatcher / NullCipher: no usable GUTI, so the network sends a
        // cleartext Identity Request before security exists and the UE answers
        // with its IMSI — the pre-security leak that survives mutual auth.
        self.emit(
            Rat::Lte,
            cid,
            Direction::UeToNet,
            Payload::LteNas(LteNasMessage::AttachRequest { guti: None }),
        );
        let (req, resp) = pre_security_identity_exchange(self.imsi.clone());
        self.emit(Rat::Lte, cid, Direction::NetToUe, Payload::LteNas(req));
        if let LteNasMessage::IdentityResponse { imsi: Some(_) } = &resp {
            self.ue.imsi_leaked = true;
        }
        self.emit(Rat::Lte, cid, Direction::UeToNet, Payload::LteNas(resp));

        if behavior == CellBehavior::NullCipher {
            // A rogue that establishes a null-protected NAS context (no real AKA).
            self.emit(
                Rat::Lte,
                cid,
                Direction::NetToUe,
                Payload::LteNas(LteNasMessage::SecurityModeCommand {
                    algorithm: NasAlgorithm::EEA0_EIA0,
                }),
            );
            self.ue.null_cipher_active = true;
            self.emit(
                Rat::Lte,
                cid,
                Direction::UeToNet,
                Payload::LteNas(LteNasMessage::SecurityModeComplete),
            );
            self.emit(
                Rat::Lte,
                cid,
                Direction::NetToUe,
                Payload::LteNas(LteNasMessage::AttachAccept { guti: None }),
            );
            return Camp::Camped;
        }

        // A plain catcher cannot complete AKA (it does not hold K): it challenges
        // with a vector built under the wrong key, the UE returns a MAC failure,
        // and the network cannot proceed — but the IMSI already leaked.
        let mut rand = [0u8; 16];
        self.rng.fill_bytes(&mut rand);
        let sqn = sqn6(self.net_sqn);
        let bogus = eps_aka_vector(&WRONG_K, &self.op_c, &rand, &sqn, &AMF, &plmn);
        self.emit(
            Rat::Lte,
            cid,
            Direction::NetToUe,
            Payload::LteNas(LteNasMessage::AuthenticationRequest {
                rand: bogus.rand,
                autn: bogus.autn,
            }),
        );
        let mut state = UeSqnState::new(self.net_sqn.saturating_sub(1));
        let outcome = ue_verify_challenge(
            &self.k,
            &self.op_c,
            &mut state,
            &bogus.rand,
            &bogus.autn,
            &plmn,
        );
        self.emit(
            Rat::Lte,
            cid,
            Direction::UeToNet,
            Payload::LteNas(outcome.to_nas()),
        );
        self.emit(
            Rat::Lte,
            cid,
            Direction::NetToUe,
            Payload::LteNas(LteNasMessage::AttachReject { cause: 0x0F }),
        );
        Camp::Camped
    }

    fn nr_exchange(
        &mut self,
        cid: CellId,
        plmn: Plmn,
        tac: u32,
        cell_id: u64,
        behavior: CellBehavior,
    ) -> Camp {
        use ocr_nr::{
            five_g_aka_vector, observer_recovers_supi, ue_authenticate, AuthenticationFailure,
            NrAlgorithm, NrNasMessage, NrRrcMessage, UeAuthResponse,
        };

        let allows_downgrade = self.ue.capabilities.allow_downgrade;
        self.emit(
            Rat::Nr,
            cid,
            Direction::NetToUe,
            Payload::NrRrc(NrRrcMessage::SystemInformation {
                plmn,
                tac,
                cell_id,
                allows_downgrade,
            }),
        );

        if behavior == CellBehavior::Downgrader {
            self.emit(
                Rat::Nr,
                cid,
                Direction::UeToNet,
                Payload::NrRrc(NrRrcMessage::SetupRequest),
            );
            self.emit(
                Rat::Nr,
                cid,
                Direction::NetToUe,
                Payload::NrRrc(NrRrcMessage::Reject { wait_time: 16 }),
            );
            return Camp::Rejected;
        }

        self.emit(
            Rat::Nr,
            cid,
            Direction::UeToNet,
            Payload::NrRrc(NrRrcMessage::SetupRequest),
        );
        self.emit(
            Rat::Nr,
            cid,
            Direction::NetToUe,
            Payload::NrRrc(NrRrcMessage::Setup),
        );

        // Registration carries a SUCI concealed under the world's scheme. Under
        // the null scheme the "ciphertext" is the plaintext MSIN, so a passive
        // observer recovers the whole SUPI — the fix configured off.
        let suci = Suci::conceal(&self.supi, &self.home, self.suci_scheme, 0, &mut self.rng);
        if observer_recovers_supi(&suci).is_some() {
            self.ue.imsi_leaked = true;
        }
        self.emit(
            Rat::Nr,
            cid,
            Direction::UeToNet,
            Payload::NrNas(NrNasMessage::RegistrationRequest {
                suci: Some(suci),
                guti: None,
            }),
        );

        // 5G-AKA still runs (a legitimate or merely null-scheme network mutually
        // authenticates the same way).
        let mut rand = [0u8; 16];
        self.rng.fill_bytes(&mut rand);
        let sqn = sqn6(self.net_sqn);
        let v = five_g_aka_vector(&self.k, &self.op_c, &rand, &sqn, &AMF, &plmn);
        self.emit(
            Rat::Nr,
            cid,
            Direction::NetToUe,
            Payload::NrNas(NrNasMessage::AuthenticationRequest {
                rand: v.rand,
                autn: v.autn,
            }),
        );
        let expected = sqn6(self.net_sqn.saturating_sub(1));
        let nas_resp =
            match ue_authenticate(&self.k, &self.op_c, &v.rand, &v.autn, &expected, &plmn) {
                UeAuthResponse::Response { res_star } => {
                    NrNasMessage::AuthenticationResponse { res_star }
                }
                UeAuthResponse::Failure(AuthenticationFailure { cause, auts }) => {
                    NrNasMessage::AuthenticationFailure { cause, auts }
                }
            };
        self.emit(Rat::Nr, cid, Direction::UeToNet, Payload::NrNas(nas_resp));
        self.net_sqn += SQN_STEP;

        let algorithm = if behavior == CellBehavior::NullCipher {
            self.ue.null_cipher_active = true;
            NrAlgorithm::NEA0_NIA0
        } else {
            NrAlgorithm::NEA2_NIA2
        };
        self.emit(
            Rat::Nr,
            cid,
            Direction::NetToUe,
            Payload::NrNas(NrNasMessage::SecurityModeCommand { algorithm }),
        );
        self.emit(
            Rat::Nr,
            cid,
            Direction::UeToNet,
            Payload::NrNas(NrNasMessage::SecurityModeComplete),
        );
        self.emit(
            Rat::Nr,
            cid,
            Direction::NetToUe,
            Payload::NrNas(NrNasMessage::RegistrationAccept { guti: None }),
        );
        Camp::Camped
    }

    /// Apply the scoring effect of a raw-injected message (see [`World::inject`]).
    fn apply_effect(&mut self, ev: &AirEvent) {
        match &ev.payload {
            Payload::Gsm(ocr_gsm::GsmMessage::IdentityResponse { imsi: Some(_) }) => {
                self.ue.imsi_leaked = true;
            }
            Payload::Gsm(ocr_gsm::GsmMessage::CipherModeCommand {
                algorithm: ocr_gsm::A5::A5_0,
            }) => {
                self.ue.null_cipher_active = true;
            }
            Payload::LteNas(ocr_lte::LteNasMessage::IdentityResponse { imsi: Some(_) }) => {
                self.ue.imsi_leaked = true;
            }
            Payload::LteNas(ocr_lte::LteNasMessage::SecurityModeCommand {
                algorithm: ocr_lte::NasAlgorithm::EEA0_EIA0,
            }) => {
                self.ue.null_cipher_active = true;
            }
            Payload::NrNas(ocr_nr::NrNasMessage::RegistrationRequest {
                suci: Some(suci), ..
            }) => {
                if ocr_nr::observer_recovers_supi(suci).is_some() {
                    self.ue.imsi_leaked = true;
                }
            }
            Payload::NrNas(ocr_nr::NrNasMessage::SecurityModeCommand {
                algorithm: ocr_nr::NrAlgorithm::NEA0_NIA0,
            }) => {
                self.ue.null_cipher_active = true;
            }
            _ => {}
        }
    }
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

/// Format a PLMN as `MCC/MNC` with significant leading zeros.
fn plmn_str(p: &Plmn) -> String {
    if p.mnc_len == 3 {
        format!("{:03}/{:03}", p.mcc, p.mnc)
    } else {
        format!("{:03}/{:02}", p.mcc, p.mnc)
    }
}

/// A human-readable one-line label for an event, for the sandbox message list.
pub fn describe(ev: &AirEvent) -> String {
    let rat = match ev.rat {
        Rat::Gsm => "2G",
        Rat::Lte => "4G",
        Rat::Nr => "5G",
    };
    let body = match &ev.payload {
        Payload::Gsm(m) => describe_gsm(m),
        Payload::LteNas(m) => describe_lte_nas(m),
        Payload::LteRrc(m) => describe_lte_rrc(m),
        Payload::NrNas(m) => describe_nr_nas(m),
        Payload::NrRrc(m) => describe_nr_rrc(m),
    };
    format!("[{} cell {}] {}", rat, ev.cell.0, body)
}

fn describe_gsm(m: &ocr_gsm::GsmMessage) -> String {
    use ocr_gsm::{GsmMessage as M, IdentityType, A5};
    match m {
        M::SystemInformation { plmn, lac, cell_id } => format!(
            "BCCH system info: PLMN {}, LAC {}, cell {}",
            plmn_str(plmn),
            lac,
            cell_id
        ),
        M::LocationUpdateRequest { tmsi } => match tmsi {
            Some(t) => format!("Location Update Request (TMSI {:#010x})", t.0),
            None => "Location Update Request (no TMSI)".into(),
        },
        M::IdentityRequest { id_type } => match id_type {
            IdentityType::Imsi => {
                "Identity Request (IMSI) — cleartext, before any security context".into()
            }
            IdentityType::Tmsi => "Identity Request (TMSI)".into(),
            IdentityType::Imei => "Identity Request (IMEI)".into(),
        },
        M::IdentityResponse { imsi } => match imsi {
            Some(i) => format!("Identity Response reveals IMSI {}", i.to_digits()),
            None => "Identity Response (no IMSI)".into(),
        },
        M::AuthenticationRequest { .. } => {
            "Authentication Request (RAND) — network challenges phone, not vice versa".into()
        }
        M::AuthenticationResponse { .. } => "Authentication Response (SRES)".into(),
        M::CipherModeCommand { algorithm } => match algorithm {
            A5::A5_0 => "Cipher Mode Command: A5/0 (null — no encryption)".into(),
            A5::A5_1 => "Cipher Mode Command: A5/1".into(),
            A5::A5_3 => "Cipher Mode Command: A5/3".into(),
        },
        M::CipherModeComplete => "Cipher Mode Complete".into(),
        M::LocationUpdateAccept { tmsi } => match tmsi {
            Some(t) => format!("Location Update Accept (new TMSI {:#010x})", t.0),
            None => "Location Update Accept".into(),
        },
        M::LocationUpdateReject { cause } => {
            format!("Location Update Reject (cause {:#04x})", cause)
        }
    }
}

fn describe_lte_nas(m: &ocr_lte::LteNasMessage) -> String {
    use ocr_lte::{LteNasMessage as M, NasAlgorithm};
    match m {
        M::AttachRequest { guti } => match guti {
            Some(_) => "Attach Request (with GUTI)".into(),
            None => "Attach Request (no GUTI — invites an identity request)".into(),
        },
        M::IdentityRequest => "Identity Request — cleartext, before security is on".into(),
        M::IdentityResponse { imsi } => match imsi {
            Some(i) => format!("Identity Response reveals IMSI {}", i.to_digits()),
            None => "Identity Response (no IMSI)".into(),
        },
        M::AuthenticationRequest { .. } => "Authentication Request (RAND, AUTN) — mutual".into(),
        M::AuthenticationResponse { .. } => "Authentication Response (RES)".into(),
        M::AuthenticationFailureSyncFailure { .. } => {
            "Authentication Failure: synch failure (this subscriber, stale SQN)".into()
        }
        M::AuthenticationFailureMacFailure => {
            "Authentication Failure: MAC failure (network could not complete auth)".into()
        }
        M::SecurityModeCommand { algorithm } => match algorithm {
            NasAlgorithm::EEA0_EIA0 => {
                "Security Mode Command: EEA0/EIA0 (null — no encryption)".into()
            }
            NasAlgorithm::EEA1_EIA1 => "Security Mode Command: EEA1/EIA1".into(),
            NasAlgorithm::EEA2_EIA2 => "Security Mode Command: EEA2/EIA2".into(),
        },
        M::SecurityModeComplete => "Security Mode Complete".into(),
        M::AttachAccept { .. } => "Attach Accept".into(),
        M::AttachReject { cause } => format!("Attach Reject (cause {:#04x}) — unprotected", cause),
        M::TrackingAreaUpdateReject { cause } => {
            format!("TAU Reject (cause {:#04x}) — unprotected", cause)
        }
        M::Paging { by_imsi } => {
            if *by_imsi {
                "Paging by IMSI".into()
            } else {
                "Paging by S-TMSI".into()
            }
        }
    }
}

fn describe_lte_rrc(m: &ocr_lte::LteRrcMessage) -> String {
    use ocr_lte::LteRrcMessage as M;
    match m {
        M::SystemInformation { plmn, tac, cell_id } => format!(
            "SIB: PLMN {}, TAC {}, cell {}",
            plmn_str(plmn),
            tac,
            cell_id
        ),
        M::ConnectionRequest => "RRC Connection Request".into(),
        M::ConnectionSetup => "RRC Connection Setup".into(),
        M::ConnectionReject { wait_time } => {
            format!("RRC Connection Reject (wait {}s) — unprotected", wait_time)
        }
        M::MeasurementReport => "Measurement Report (leaks neighbour view)".into(),
    }
}

fn describe_nr_nas(m: &ocr_nr::NrNasMessage) -> String {
    use ocr_nr::{AuthFailureCause, NrAlgorithm, NrNasMessage as M};
    match m {
        M::RegistrationRequest { suci, .. } => match suci {
            Some(s) if s.is_protected() => "Registration Request (SUCI, concealed)".into(),
            Some(_) => "Registration Request (SUCI, NULL scheme — SUPI in clear)".into(),
            None => "Registration Request (with 5G-GUTI)".into(),
        },
        M::IdentityRequestSuci => "Identity Request (SUCI) — asks for the concealed id".into(),
        M::IdentityResponseSuci { suci } => {
            if suci.is_protected() {
                "Identity Response (SUCI, concealed)".into()
            } else {
                "Identity Response (SUCI, NULL scheme — SUPI in clear)".into()
            }
        }
        M::AuthenticationRequest { .. } => "Authentication Request (RAND, AUTN) — mutual".into(),
        M::AuthenticationResponse { .. } => "Authentication Response (RES*)".into(),
        M::AuthenticationFailure { cause, .. } => match cause {
            AuthFailureCause::MacFailure => {
                "Authentication Failure: MAC failure (not this subscriber)".into()
            }
            AuthFailureCause::SynchFailure => {
                "Authentication Failure: synch failure (this subscriber — a linkability oracle)"
                    .into()
            }
        },
        M::SecurityModeCommand { algorithm } => match algorithm {
            NrAlgorithm::NEA0_NIA0 => {
                "Security Mode Command: NEA0/NIA0 (null — no encryption)".into()
            }
            NrAlgorithm::NEA1_NIA1 => "Security Mode Command: NEA1/NIA1".into(),
            NrAlgorithm::NEA2_NIA2 => "Security Mode Command: NEA2/NIA2".into(),
        },
        M::SecurityModeComplete => "Security Mode Complete".into(),
        M::RegistrationAccept { .. } => "Registration Accept".into(),
        M::RegistrationReject { cause } => {
            format!("Registration Reject (cause {:#04x}) — unprotected", cause)
        }
    }
}

fn describe_nr_rrc(m: &ocr_nr::NrRrcMessage) -> String {
    use ocr_nr::NrRrcMessage as M;
    match m {
        M::SystemInformation {
            plmn,
            tac,
            cell_id,
            allows_downgrade,
        } => format!(
            "SIB: PLMN {}, TAC {}, cell {}{}",
            plmn_str(plmn),
            tac,
            cell_id,
            if *allows_downgrade {
                " (allows fallback)"
            } else {
                ""
            }
        ),
        M::SetupRequest => "RRC Setup Request".into(),
        M::Setup => "RRC Setup".into(),
        M::Reject { wait_time } => format!("RRC Reject (wait {}s) — unprotected", wait_time),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_leak_event(w: &World) -> bool {
        w.events().iter().any(|e| {
            matches!(
                &e.payload,
                Payload::Gsm(ocr_gsm::GsmMessage::IdentityResponse { imsi: Some(_) })
                    | Payload::LteNas(ocr_lte::LteNasMessage::IdentityResponse { imsi: Some(_) })
            )
        })
    }

    #[test]
    fn rogue_gsm_catcher_leaks_imsi_and_camps() {
        let mut w = World::new();
        let rogue = w.add_rogue(Rat::Gsm, -40, CellBehavior::IdentityCatcher);
        w.step(1_000_000);

        assert!(w.ue.imsi_leaked, "the IMSI must leak to a 2G catcher");
        assert_eq!(w.ue.camped_on, Some(rogue));
        assert_eq!(w.ue.camped_rat, Some(Rat::Gsm));
        // The leak is visible on the air, not just in scoring state.
        assert!(find_leak_event(&w));
    }

    #[test]
    fn legit_only_world_never_leaks() {
        let mut w = World::new();
        let cell = w.add_legit(Rat::Lte, -50);
        w.step(1_000_000);

        assert!(!w.ue.imsi_leaked, "a legitimate network must not leak");
        assert!(!w.ue.null_cipher_active);
        assert_eq!(w.ue.camped_on, Some(cell));
        assert_eq!(w.ue.camped_rat, Some(Rat::Lte));
        assert!(!find_leak_event(&w));
    }

    #[test]
    fn legit_gsm_authenticates_without_leaking() {
        let mut w = World::new();
        w.add_legit(Rat::Gsm, -50);
        w.step(1_000_000);
        assert!(!w.ue.imsi_leaked);
        assert!(!w.ue.null_cipher_active);
        // A real cipher was negotiated, not the null one.
        assert!(w.events().iter().any(|e| matches!(
            &e.payload,
            Payload::Gsm(ocr_gsm::GsmMessage::CipherModeCommand {
                algorithm: ocr_gsm::A5::A5_1
            })
        )));
    }

    #[test]
    fn nr_profile_a_conceals_but_null_scheme_leaks() {
        // Default scheme is Profile A: the SUPI stays concealed.
        let mut protected = World::new();
        protected.add_legit(Rat::Nr, -45);
        protected.step(1_000_000);
        assert!(
            !protected.ue.imsi_leaked,
            "Profile A SUCI conceals the SUPI"
        );
        assert_eq!(protected.ue.camped_rat, Some(Rat::Nr));

        // Turn the fix off: the null scheme puts the SUPI on the air.
        let mut null = World::new();
        null.set_suci_scheme(ProtectionScheme::Null);
        null.add_legit(Rat::Nr, -45);
        null.step(1_000_000);
        assert!(
            null.ue.imsi_leaked,
            "null-scheme SUCI exposes the SUPI to a passive observer"
        );
    }

    #[test]
    fn lte_to_2g_downgrade_lands_on_gsm_catcher() {
        let mut w = World::new();
        // The rogue LTE cell out-signals everything and rejects; the only cell the
        // UE can fall to is a 2G catcher.
        w.add_rogue(Rat::Lte, -35, CellBehavior::Downgrader);
        let gsm = w.add_rogue(Rat::Gsm, -45, CellBehavior::IdentityCatcher);
        w.step(1_000_000);

        assert_eq!(w.ue.camped_rat, Some(Rat::Gsm), "bidding-down ends on 2G");
        assert_eq!(w.ue.camped_on, Some(gsm));
        assert!(w.ue.imsi_leaked, "the 2G catcher then grabs the IMSI");
        // The unprotected reject that drove the downgrade is on the air.
        assert!(w.events().iter().any(|e| matches!(
            &e.payload,
            Payload::LteRrc(ocr_lte::LteRrcMessage::ConnectionReject { .. })
        )));
    }

    #[test]
    fn downgrade_defence_refuses_to_fall_to_2g() {
        let mut w = World::new();
        w.ue.capabilities.allow_downgrade = false;
        w.add_rogue(Rat::Lte, -35, CellBehavior::Downgrader);
        w.add_rogue(Rat::Gsm, -45, CellBehavior::IdentityCatcher);
        w.step(1_000_000);

        // The LTE cell rejected and got barred; with downgrade off, the UE will
        // not drop to the 2G cell, so it camps on nothing and nothing leaks.
        assert_eq!(w.ue.camped_on, None);
        assert!(!w.ue.imsi_leaked);
    }

    #[test]
    fn null_cipher_forcer_sets_flag() {
        let mut w = World::new();
        w.add_rogue(Rat::Gsm, -40, CellBehavior::NullCipher);
        w.step(1_000_000);
        assert!(w.ue.null_cipher_active);
        assert!(w.ue.imsi_leaked);
        assert!(w.events().iter().any(|e| matches!(
            &e.payload,
            Payload::Gsm(ocr_gsm::GsmMessage::CipherModeCommand {
                algorithm: ocr_gsm::A5::A5_0
            })
        )));
    }

    #[test]
    fn lte_catcher_leaks_before_security() {
        let mut w = World::new();
        let rogue = w.add_rogue(Rat::Lte, -40, CellBehavior::IdentityCatcher);
        w.step(1_000_000);
        assert!(w.ue.imsi_leaked);
        assert_eq!(w.ue.camped_on, Some(rogue));
        assert_eq!(w.ue.camped_rat, Some(Rat::Lte));
        // The network could not complete authentication.
        assert!(w.events().iter().any(|e| matches!(
            &e.payload,
            Payload::LteNas(ocr_lte::LteNasMessage::AuthenticationFailureMacFailure)
        )));
    }

    #[test]
    fn best_cell_picks_the_strongest_allowed() {
        let mut w = World::new();
        let _weak = w.add_legit(Rat::Lte, -80);
        let strong = w.add_rogue(Rat::Gsm, -30, CellBehavior::IdentityCatcher);
        assert_eq!(w.best_cell(), Some(strong));

        // Disallow GSM: the UE now prefers the weaker LTE cell.
        w.ue.capabilities.allow_gsm = false;
        assert_eq!(w.best_cell(), Some(_weak));
    }

    #[test]
    fn inject_records_and_applies_effect() {
        let mut w = World::new();
        let ev = AirEvent {
            t_us: 5_000,
            rat: Rat::Gsm,
            cell: CellId(7),
            dir: Direction::UeToNet,
            payload: Payload::Gsm(ocr_gsm::GsmMessage::IdentityResponse {
                imsi: Some(w.imsi.clone()),
            }),
        };
        w.inject(ev);
        assert_eq!(w.events().len(), 1);
        assert!(w.ue.imsi_leaked, "injected cleartext IMSI marks a leak");
        assert!(w.now_us >= 5_000);
    }

    #[test]
    fn describe_is_nonempty_for_every_emitted_event() {
        let mut w = World::new();
        w.add_rogue(Rat::Nr, -40, CellBehavior::NullCipher);
        w.step(1_000_000);
        assert!(!w.events().is_empty());
        for e in w.events() {
            let line = describe(e);
            assert!(!line.is_empty());
            assert!(line.starts_with('['));
        }
    }

    #[test]
    fn same_seed_produces_identical_events() {
        let build = || {
            let mut w = World::with_seed(0xBEEF_CAFE);
            // A scenario that exercises the RNG heavily: NR Profile A (ephemeral
            // ECIES key) plus GSM and LTE auth challenges.
            w.add_legit(Rat::Nr, -45);
            w.step(1_000_000);
            w
        };
        let a = build();
        let b = build();
        assert_eq!(a.events(), b.events(), "same seed ⇒ identical air");
        assert!(!a.events().is_empty());
    }

    #[test]
    fn different_seed_changes_profile_a_ephemeral_key() {
        let run = |seed: u64| {
            let mut w = World::with_seed(seed);
            w.add_legit(Rat::Nr, -45);
            w.step(1_000_000);
            w.events().to_vec()
        };
        // The concealed SUCI's ephemeral key comes from the seed, so the on-air
        // bytes differ between seeds even though the message shape is the same.
        assert_ne!(run(1), run(2));
    }

    #[test]
    fn repeated_steps_do_not_re_run_a_stable_camp() {
        let mut w = World::new();
        w.add_legit(Rat::Lte, -50);
        w.step(1_000_000);
        let after_first = w.events().len();
        w.step(1_000_000);
        assert_eq!(
            w.events().len(),
            after_first,
            "a stable camp emits nothing new on the next step"
        );
    }
}
