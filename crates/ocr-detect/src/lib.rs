//! The defensive half of Open Cell Range — a passive, Rayhunter-class monitor.
//!
//! A [`Monitor`] consumes the [`AirEvent`] stream a `World` produces and states
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
//! ## The heuristics, and why each is (and is not) an alarm
//!
//! Every heuristic maps to a documented real-world detection. The recurring
//! design tension is false positives: a detector that cries wolf teaches the
//! wrong lesson, so each rule below is written to fire on the *low-false-positive*
//! shape of the signal, and the reasoning is stated inline where the rule lives.
//!
//! - **Cleartext identity request** (`High`) — a permanent-identity request
//!   (`GsmMessage::IdentityRequest{IMSI}`, `LteNasMessage::IdentityRequest`) seen
//!   before a protected security context exists. The classic IMSI-catcher lever
//!   (Rayhunter/SnoopSnitch "IMSI requested"). Note it also happens on a genuine
//!   first attach with no valid temporary id — so it means *the permanent id was
//!   exposed*, which is worth surfacing regardless of intent, not *an attack is
//!   proven*.
//! - **Null cipher / null algorithm** (`High`) — `A5/0`, `EEA0/EIA0`, `NEA0/NIA0`.
//!   Rayhunter's flagship heuristic. Legal for emergency calls, so still a signal
//!   rather than proof, but on an ordinary subscriber attach it is a strong tell.
//! - **Forced downgrade** (`High` to GSM, `Medium` otherwise) — the camped RAT
//!   descending a generation. Legitimate in poor coverage; a drop straight to 2G
//!   strips the subscriber back to the broken-by-design generation, which is the
//!   aLTEr/LTEInspector bidding-down goal.
//! - **Unprotected pre-auth reject** (`High`) — an `AttachReject`/`TAU Reject`/
//!   `RegistrationReject`/RRC `ConnectionReject`/NR `Reject` arriving before any
//!   protected context. These are unauthenticated, so anyone can spoof them; the
//!   LTEInspector/aLTEr DoS + bidding-down family. A lone congestion reject looks
//!   identical, which is exactly *why* they are dangerous — an integrity-protected
//!   reject (after security is up) is trustworthy and is deliberately not flagged.
//! - **Unexpected / implausible cell identity** (`Medium`) — a `SystemInformation`
//!   broadcast whose LAC/TAC/cell id is a reserved value (e.g. `0x0000`, the
//!   reserved maxima `0xFFFF`/`0xFFFFFF`). A conforming cell never broadcasts these.
//! - **Location area jumped** (`Medium`) — a *previously seen* cell that now
//!   advertises a different area code (or PLMN/cell id). A fixed cell's broadcast
//!   identity is stable; changing it is a rogue-cell tell. Note a bare LAC/TAC
//!   change *across different cells* is ordinary reselection and is NOT flagged.
//! - **Authentication never completed** (`Medium`) — an auth challenge was issued
//!   but the exchange reselected away without ever reaching a protected security
//!   context (a fake cell that cannot finish AKA and gives up). `Medium`, because a
//!   genuine network can also abandon an attach.
//! - **Network authentication failed** (`High`) — the UE reported a *MAC failure*
//!   (`AuthenticationFailureMacFailure`, NR `MacFailure`). A network that holds the
//!   subscriber key never produces this; it means the far side could not prove it
//!   knows `K` — a keyless fake cell. Bit errors are the only benign cause and are
//!   transient.
//! - **Null SUCI scheme** (`High`) — a 5G identity that is a null-scheme SUCI, i.e.
//!   the SUPI in the clear (TS 33.501 Protection Scheme 0). Spec-legal but defeats
//!   5G's core identity protection.
//! - **Reject storm** (`Medium`) — repeated unprotected rejects in a short window:
//!   targeted DoS / bidding-down pressure. A single reject is normal; the storm is
//!   the attack.
//! - **IMSI paging** (`Medium`) — `Paging{by_imsi:true}`. Paging by the permanent
//!   identity rather than a temporary one is the ToRPEDO/PIERCER presence-confirmation
//!   pattern; a well-behaved network pages by S-TMSI.
//! - **Linkability probe** (`Low`) — both a MAC failure and a synch failure seen on
//!   one RAT. A normal attach yields at most one failure of one type; a *mix* is the
//!   AKA failure-message oracle (TS 33.501 linkability) being exercised, e.g. an
//!   `AUTN` being replayed to test whether it belongs to the target. Kept `Low`
//!   because synch failures also occur from ordinary SQN drift.
//!
//! Note on signal strength: [`AirEvent`] deliberately carries no signal-strength
//! field, and it cannot be inferred from message content, so
//! [`FindingKind::ImplausibleSignalStrength`] is retained for API stability and the
//! capture/replay seam but this monitor never emits it.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use ocr_air::{AirEvent, CellId, Payload, Rat};
use ocr_gsm::{GsmMessage, IdentityType, A5};
use ocr_identity::Plmn;
use ocr_lte::{LteNasMessage, LteRrcMessage, NasAlgorithm};
use ocr_nr::{AuthFailureCause, NrAlgorithm, NrNasMessage, NrRrcMessage};

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
///
/// New variants may be appended; downstream code should treat unknown kinds by
/// their [`FindingKind::as_str`] display string rather than assuming a closed set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingKind {
    /// A permanent-identity request seen before a protected security context.
    CleartextIdentityRequest,
    /// A null ciphering / null NAS algorithm was commanded.
    NullCipherCommanded,
    /// The camped RAT dropped to a lower generation.
    ForcedDowngrade,
    /// A `SystemInformation` broadcast carried a reserved / implausible identity.
    UnexpectedCellIdentity,
    /// A cell that was seen before now advertises a different area code / identity.
    LocationAreaJumped,
    /// An authentication challenge never reached a protected security context.
    AuthenticationNeverCompleted,
    /// Retained for the capture/replay seam; never emitted (no signal in `AirEvent`).
    ImplausibleSignalStrength,
    /// Repeated unprotected rejects in a short window.
    RejectStorm,
    /// A 5G identity that was a null-scheme SUCI (SUPI in the clear).
    NullSuciScheme,
    /// An unprotected pre-auth reject — the bidding-down / DoS lever.
    UnprotectedReject,
    /// The UE reported a MAC failure: the network could not prove it holds `K`.
    NetworkAuthenticationFailed,
    /// Paging by the permanent identity (IMSI) rather than a temporary one.
    ImsiPaging,
    /// The AKA failure-message linkability oracle appears to be in use.
    LinkabilityProbe,
}

impl FindingKind {
    /// A stable, human-facing display string. The site renders [`Finding::kind`]
    /// through this, so the names are chosen to read on their own.
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingKind::CleartextIdentityRequest => "Cleartext identity request",
            FindingKind::NullCipherCommanded => "Null cipher commanded",
            FindingKind::ForcedDowngrade => "Forced downgrade",
            FindingKind::UnexpectedCellIdentity => "Unexpected cell identity",
            FindingKind::LocationAreaJumped => "Location area jumped",
            FindingKind::AuthenticationNeverCompleted => "Authentication never completed",
            FindingKind::ImplausibleSignalStrength => "Implausible signal strength",
            FindingKind::RejectStorm => "Reject storm",
            FindingKind::NullSuciScheme => "Null SUCI scheme",
            FindingKind::UnprotectedReject => "Unprotected reject",
            FindingKind::NetworkAuthenticationFailed => "Network authentication failed",
            FindingKind::ImsiPaging => "IMSI paging",
            FindingKind::LinkabilityProbe => "Linkability probe",
        }
    }
}

impl core::fmt::Display for FindingKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
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

/// What a cell claimed about its own identity the last time we heard its
/// `SystemInformation`. A fixed cell's identity is stable, so a later mismatch is
/// the anomaly the identity heuristics key on.
#[derive(Clone, Copy)]
struct CellIdentity {
    cell: CellId,
    plmn: Plmn,
    /// LAC (GSM) / TAC (LTE, NR) as a common width.
    area_code: u64,
    /// The cell id the broadcast *claimed* (distinct from the opaque air `CellId`).
    claimed_cell: u64,
}

/// Sliding window and threshold for the reject-storm heuristic.
const REJECT_STORM_WINDOW_US: u64 = 10_000_000; // 10 virtual seconds
const REJECT_STORM_THRESHOLD: usize = 3;

/// A passive monitor. Feed it events; ask it for findings.
///
/// State is carried across [`Monitor::observe`] calls: the currently camped cell
/// and RAT, whether a protected security context has been established on it,
/// whether an auth challenge is outstanding, the identities cells have claimed,
/// and the recent reject history. That state is what lets stateless-looking
/// messages ("a reject", "an SI") be judged in context.
#[derive(Default)]
pub struct Monitor {
    findings: Vec<Finding>,

    // --- camping / reselection ------------------------------------------------
    /// The opaque air cell we are currently hearing the serving exchange from.
    camped_cell: Option<CellId>,
    /// The RAT of the currently camped cell.
    camped_rat: Option<Rat>,

    // --- per-camping-session security state -----------------------------------
    /// A non-null security mode completed on the current cell.
    protected_context: bool,
    /// An `AuthenticationRequest` is outstanding with no completion yet.
    auth_challenge_open: bool,
    /// The most recent security-mode command on this cell commanded a null algorithm.
    last_cmd_was_null: bool,

    // --- identity stability ---------------------------------------------------
    /// What each opaque cell has claimed in `SystemInformation`.
    seen_cells: Vec<CellIdentity>,

    // --- reject storm ---------------------------------------------------------
    /// Timestamps of recent *unprotected* rejects, pruned to the window.
    reject_times: Vec<u64>,
    /// Latched so a single storm is reported once, then re-armed when it clears.
    reject_storm_open: bool,

    // --- linkability oracle ---------------------------------------------------
    saw_mac_failure: bool,
    saw_synch_failure: bool,
    linkability_flagged: bool,
}

impl Monitor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe one event, possibly producing findings.
    pub fn observe(&mut self, ev: &AirEvent) {
        // Reselection bookkeeping first: a change of the serving cell resets the
        // per-session security judgement, and is where downgrade / abandoned-auth
        // are concluded about the cell we are leaving.
        self.track_camping(ev);

        match &ev.payload {
            Payload::Gsm(m) => self.observe_gsm(ev, m),
            Payload::LteNas(m) => self.observe_lte_nas(ev, m),
            Payload::LteRrc(m) => self.observe_lte_rrc(ev, m),
            Payload::NrNas(m) => self.observe_nr_nas(ev, m),
            Payload::NrRrc(m) => self.observe_nr_rrc(ev, m),
        }
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

    // ---- internals -----------------------------------------------------------

    fn record(&mut self, kind: FindingKind, severity: Severity, t_us: u64, detail: String) {
        self.findings.push(Finding {
            kind,
            severity,
            t_us,
            detail,
        });
    }

    /// Generation rank for downgrade comparison: higher is newer.
    fn gen_rank(rat: Rat) -> u8 {
        match rat {
            Rat::Gsm => 0,
            Rat::Lte => 1,
            Rat::Nr => 2,
        }
    }

    /// Detect (re)selection to a new serving cell and, on it, conclude what can be
    /// said about the cell being left, then reset the per-session state.
    ///
    /// Keying on the opaque air `CellId` (not the broadcast's claimed cell id)
    /// means an attacker cell that leads with anything — even a reject or an
    /// identity request, not an SI — is still recognised as a new camping context,
    /// so a pre-auth catch on it is not masked by the previous cell's completed
    /// security context.
    fn track_camping(&mut self, ev: &AirEvent) {
        match self.camped_cell {
            Some(prev) if prev != ev.cell => {
                // Authentication that never completed on the cell we are leaving:
                // a challenge went out but no protected context was ever reached —
                // the shape of a fake cell that cannot finish AKA and gives up.
                // Medium, because a genuine network can also abandon an attach.
                if self.auth_challenge_open && !self.protected_context {
                    self.record(
                        FindingKind::AuthenticationNeverCompleted,
                        Severity::Medium,
                        ev.t_us,
                        String::from(
                            "Auth challenge was issued but the exchange reselected away \
                             before any protected security context — consistent with a cell \
                             that cannot complete mutual authentication.",
                        ),
                    );
                }

                // Forced downgrade: the camped RAT descending a generation.
                if let Some(prev_rat) = self.camped_rat {
                    if Self::gen_rank(ev.rat) < Self::gen_rank(prev_rat) {
                        let (severity, detail) = if ev.rat == Rat::Gsm {
                            (
                                Severity::High,
                                "Camped RAT dropped to 2G/GSM, the generation with one-way \
                                 auth and optional encryption — the bidding-down goal. \
                                 Legitimate only in genuine loss of higher-RAT coverage.",
                            )
                        } else {
                            (
                                Severity::Medium,
                                "Camped RAT dropped a generation. Ordinary in poor coverage, \
                                 but the lever bidding-down attacks pull.",
                            )
                        };
                        self.record(
                            FindingKind::ForcedDowngrade,
                            severity,
                            ev.t_us,
                            String::from(detail),
                        );
                    }
                }

                // Fresh cell: nothing is proven about its security yet.
                self.protected_context = false;
                self.auth_challenge_open = false;
                self.last_cmd_was_null = false;
                self.camped_cell = Some(ev.cell);
                self.camped_rat = Some(ev.rat);
            }
            Some(_) => { /* same serving cell: keep the session state */ }
            None => {
                self.camped_cell = Some(ev.cell);
                self.camped_rat = Some(ev.rat);
            }
        }
    }

    /// The identity-stability + reserved-value checks for any `SystemInformation`.
    ///
    /// `area_code` is the LAC (GSM) or TAC (LTE/NR); `claimed_cell` is the cell id
    /// the broadcast declared, widened to `u64`. `reserved` is precomputed by the
    /// caller against that RAT's reserved ranges.
    fn check_system_information(
        &mut self,
        ev: &AirEvent,
        plmn: Plmn,
        area_code: u64,
        claimed_cell: u64,
        reserved: bool,
    ) {
        // Look for a prior claim from this exact opaque cell.
        let prior = self.seen_cells.iter().position(|c| c.cell == ev.cell);

        match prior {
            None => {
                self.seen_cells.push(CellIdentity {
                    cell: ev.cell,
                    plmn,
                    area_code,
                    claimed_cell,
                });
                // Reserved-value check only on first sighting, so a periodic
                // rebroadcast of the same bad SI is not re-flagged every time.
                if reserved {
                    self.record(
                        FindingKind::UnexpectedCellIdentity,
                        Severity::Medium,
                        ev.t_us,
                        String::from(
                            "SystemInformation advertised a reserved / implausible LAC/TAC or \
                             cell id (e.g. 0x0000 or the reserved maximum) — a conforming cell \
                             never broadcasts these.",
                        ),
                    );
                }
            }
            Some(idx) => {
                let old = self.seen_cells[idx];
                if old.area_code != area_code
                    || old.plmn != plmn
                    || old.claimed_cell != claimed_cell
                {
                    // The SAME physical/air cell changed what it claims. A bare
                    // area change across DIFFERENT cells is ordinary reselection
                    // and never reaches here (different opaque `CellId`), which is
                    // deliberate: it is the source of most false positives.
                    if old.area_code != area_code && old.plmn == plmn {
                        self.record(
                            FindingKind::LocationAreaJumped,
                            Severity::Medium,
                            ev.t_us,
                            String::from(
                                "A cell that was seen before now advertises a different area \
                                 code for the same PLMN. A fixed cell's LAC/TAC is stable; a \
                                 change on the same cell is a rogue-cell tell.",
                            ),
                        );
                    } else {
                        self.record(
                            FindingKind::UnexpectedCellIdentity,
                            Severity::Medium,
                            ev.t_us,
                            String::from(
                                "A cell that was seen before now claims a different PLMN or cell \
                                 id — its broadcast identity should be stable.",
                            ),
                        );
                    }
                    self.seen_cells[idx] = CellIdentity {
                        cell: ev.cell,
                        plmn,
                        area_code,
                        claimed_cell,
                    };
                }
            }
        }
    }

    /// Establish (or fail to establish) the per-session security context on
    /// completion of a security-mode / cipher-mode handshake.
    fn on_security_mode_complete(&mut self) {
        // A completed *null* handshake still leaves traffic unprotected — the
        // teaching point — so it does NOT set `protected_context`.
        self.protected_context = !self.last_cmd_was_null;
        self.auth_challenge_open = false;
    }

    /// Note an unprotected reject and evaluate the reject-storm window.
    fn note_unprotected_reject(&mut self, t_us: u64) {
        self.reject_times.push(t_us);
        let cutoff = t_us.saturating_sub(REJECT_STORM_WINDOW_US);
        self.reject_times.retain(|&t| t >= cutoff);

        if self.reject_times.len() >= REJECT_STORM_THRESHOLD {
            if !self.reject_storm_open {
                self.reject_storm_open = true;
                self.record(
                    FindingKind::RejectStorm,
                    Severity::Medium,
                    t_us,
                    String::from(
                        "Several unprotected rejects in a short window — targeted denial of \
                         service or sustained bidding-down pressure, not a lone transient reject.",
                    ),
                );
            }
        } else {
            self.reject_storm_open = false;
        }
    }

    /// Both AKA failure types seen: the failure-message oracle is being exercised.
    fn check_linkability(&mut self, t_us: u64) {
        if self.saw_mac_failure && self.saw_synch_failure && !self.linkability_flagged {
            self.linkability_flagged = true;
            self.record(
                FindingKind::LinkabilityProbe,
                Severity::Low,
                t_us,
                String::from(
                    "Both a MAC failure and a synch failure were observed — a normal attach \
                     yields at most one. The distinguishable AKA failure messages are a known \
                     linkability oracle (an AUTN can be replayed to test if it is the target's).",
                ),
            );
        }
    }

    // ---- per-RAT handlers ----------------------------------------------------

    fn observe_gsm(&mut self, ev: &AirEvent, m: &GsmMessage) {
        match m {
            GsmMessage::SystemInformation { plmn, lac, cell_id } => {
                // TS 24.008 §10.5.1.3: LAC 0x0000 and 0xFFFE are reserved; 0xFFFF
                // is the "not yet assigned" catch-all. A cell id of 0xFFFF is the
                // reserved maximum.
                let reserved =
                    *lac == 0x0000 || *lac == 0xFFFE || *lac == 0xFFFF || *cell_id == 0xFFFF;
                self.check_system_information(ev, *plmn, *lac as u64, *cell_id as u64, reserved);
            }
            GsmMessage::IdentityRequest { id_type } => {
                // Requesting the *permanent* identity before a protected context is
                // the 2G IMSI-catcher lever. A TMSI/IMEI request is not the
                // permanent-id leak and is not flagged.
                if matches!(id_type, IdentityType::Imsi) && !self.protected_context {
                    self.record(
                        FindingKind::CleartextIdentityRequest,
                        Severity::High,
                        ev.t_us,
                        String::from(
                            "IMSI was requested with no protected security context — the \
                             permanent identity is exposed in the clear. The core IMSI-catcher \
                             behaviour; also occurs on a genuine first attach, so it flags \
                             exposure rather than proving intent.",
                        ),
                    );
                }
            }
            GsmMessage::AuthenticationRequest { .. } => {
                self.auth_challenge_open = true;
            }
            GsmMessage::CipherModeCommand { algorithm } => {
                self.last_cmd_was_null = matches!(algorithm, A5::A5_0);
                if self.last_cmd_was_null {
                    self.record(
                        FindingKind::NullCipherCommanded,
                        Severity::High,
                        ev.t_us,
                        String::from(
                            "Network commanded A5/0 (null encryption); GSM gives the phone no \
                             way to refuse. Legal for emergency calls, but on an ordinary attach \
                             it is a rogue-BTS tell.",
                        ),
                    );
                }
            }
            GsmMessage::CipherModeComplete => self.on_security_mode_complete(),
            // GSM is already the bottom of the downgrade ladder and legitimate
            // rejects of genuinely-barred phones are common, so this is not a
            // standalone bidding-down finding — but an unprotected one still feeds
            // the storm.
            GsmMessage::LocationUpdateReject { .. } if !self.protected_context => {
                self.note_unprotected_reject(ev.t_us);
            }
            _ => {}
        }
    }

    fn observe_lte_nas(&mut self, ev: &AirEvent, m: &LteNasMessage) {
        match m {
            LteNasMessage::IdentityRequest => {
                // LTE identity requests are, by design, sent before the security
                // context and answered with the IMSI; before a protected context
                // that is a cleartext permanent-identity exposure.
                if !self.protected_context {
                    self.record(
                        FindingKind::CleartextIdentityRequest,
                        Severity::High,
                        ev.t_us,
                        String::from(
                            "NAS Identity Request before a protected security context — the UE \
                             answers with its IMSI in the clear. Closed only after AKA, which is \
                             too late for the identity already handed over.",
                        ),
                    );
                }
            }
            LteNasMessage::AuthenticationRequest { .. } => {
                self.auth_challenge_open = true;
            }
            LteNasMessage::AuthenticationFailureMacFailure => {
                // The UE could not verify the network's AUTN MAC: the far side does
                // not hold K. A legitimate network never triggers this.
                self.saw_mac_failure = true;
                self.record(
                    FindingKind::NetworkAuthenticationFailed,
                    Severity::High,
                    ev.t_us,
                    String::from(
                        "UE reported a MAC failure: the network's AUTN did not verify, so it \
                         could not prove it holds the subscriber key — a keyless fake cell. \
                         (Transient bit errors are the only benign cause.)",
                    ),
                );
                self.check_linkability(ev.t_us);
            }
            LteNasMessage::AuthenticationFailureSyncFailure { .. } => {
                self.saw_synch_failure = true;
                self.check_linkability(ev.t_us);
            }
            LteNasMessage::SecurityModeCommand { algorithm } => {
                self.last_cmd_was_null = matches!(algorithm, NasAlgorithm::EEA0_EIA0);
                if self.last_cmd_was_null {
                    self.record(
                        FindingKind::NullCipherCommanded,
                        Severity::High,
                        ev.t_us,
                        String::from(
                            "NAS Security Mode Command selected the null pair EEA0/EIA0 — no \
                             confidentiality and no integrity. Legal, but it strips LTE's \
                             protection back to nothing.",
                        ),
                    );
                }
            }
            LteNasMessage::SecurityModeComplete => self.on_security_mode_complete(),
            LteNasMessage::AttachReject { .. } | LteNasMessage::TrackingAreaUpdateReject { .. }
                if !self.protected_context =>
            {
                self.record(
                    FindingKind::UnprotectedReject,
                    Severity::High,
                    ev.t_us,
                    String::from(
                        "Unprotected NAS reject before any security context. It is \
                         unauthenticated, so anyone can spoof it to steer the UE off LTE \
                         (bidding-down) or deny it service — the LTEInspector/aLTEr lever.",
                    ),
                );
                self.note_unprotected_reject(ev.t_us);
            }
            LteNasMessage::Paging { by_imsi: true } => {
                self.record(
                    FindingKind::ImsiPaging,
                    Severity::Medium,
                    ev.t_us,
                    String::from(
                        "Paging by IMSI rather than a temporary id. A well-behaved network \
                         pages by S-TMSI; IMSI paging is the ToRPEDO/PIERCER presence-\
                         confirmation pattern.",
                    ),
                );
            }
            _ => {}
        }
    }

    fn observe_lte_rrc(&mut self, ev: &AirEvent, m: &LteRrcMessage) {
        match m {
            LteRrcMessage::SystemInformation { plmn, tac, cell_id } => {
                // TS 23.003: TAC 0x0000 and 0xFFFE are reserved, 0xFFFF is the "not
                // assigned" value. A u32 cell id of all-ones is outside the 28-bit
                // E-UTRAN cell id range, hence implausible.
                let reserved =
                    *tac == 0x0000 || *tac == 0xFFFE || *tac == 0xFFFF || *cell_id == 0xFFFF_FFFF;
                self.check_system_information(ev, *plmn, *tac as u64, *cell_id as u64, reserved);
            }
            LteRrcMessage::ConnectionReject { .. } if !self.protected_context => {
                self.record(
                    FindingKind::UnprotectedReject,
                    Severity::High,
                    ev.t_us,
                    String::from(
                        "Unprotected RRC Connection Reject before any security context — a \
                         spoofable back-off that denies the UE its connection (DoS / \
                         bidding-down pressure).",
                    ),
                );
                self.note_unprotected_reject(ev.t_us);
            }
            _ => {}
        }
    }

    fn observe_nr_nas(&mut self, ev: &AirEvent, m: &NrNasMessage) {
        match m {
            NrNasMessage::RegistrationRequest {
                suci: Some(suci), ..
            } => {
                if !suci.is_protected() {
                    self.record(
                        FindingKind::NullSuciScheme,
                        Severity::High,
                        ev.t_us,
                        String::from(
                            "Registration carried a null-scheme SUCI: the SUPI travelled in the \
                             clear (TS 33.501 Protection Scheme 0). Spec-legal, but it defeats \
                             5G's core identity concealment.",
                        ),
                    );
                }
            }
            NrNasMessage::IdentityResponseSuci { suci } => {
                if !suci.is_protected() {
                    self.record(
                        FindingKind::NullSuciScheme,
                        Severity::High,
                        ev.t_us,
                        String::from(
                            "Identity response was a null-scheme SUCI — the SUPI is exposed in \
                             the clear, the very capture 5G's concealment was meant to end.",
                        ),
                    );
                }
            }
            NrNasMessage::AuthenticationRequest { .. } => {
                self.auth_challenge_open = true;
            }
            NrNasMessage::AuthenticationFailure { cause, .. } => match cause {
                AuthFailureCause::MacFailure => {
                    self.saw_mac_failure = true;
                    self.record(
                        FindingKind::NetworkAuthenticationFailed,
                        Severity::High,
                        ev.t_us,
                        String::from(
                            "UE reported a 5G MAC failure: the network's AUTN did not verify, so \
                             it could not prove it holds the subscriber key — a keyless fake cell.",
                        ),
                    );
                    self.check_linkability(ev.t_us);
                }
                AuthFailureCause::SynchFailure => {
                    self.saw_synch_failure = true;
                    self.check_linkability(ev.t_us);
                }
            },
            NrNasMessage::SecurityModeCommand { algorithm } => {
                self.last_cmd_was_null = matches!(algorithm, NrAlgorithm::NEA0_NIA0);
                if self.last_cmd_was_null {
                    self.record(
                        FindingKind::NullCipherCommanded,
                        Severity::High,
                        ev.t_us,
                        String::from(
                            "5G Security Mode Command selected the null pair NEA0/NIA0 — no \
                             confidentiality and no integrity on NAS.",
                        ),
                    );
                }
            }
            NrNasMessage::SecurityModeComplete => self.on_security_mode_complete(),
            NrNasMessage::RegistrationReject { .. } if !self.protected_context => {
                self.record(
                    FindingKind::UnprotectedReject,
                    Severity::High,
                    ev.t_us,
                    String::from(
                        "Unprotected 5G Registration Reject before any security context — a \
                         spoofable steer that can push the UE toward a downgraded RAT or deny \
                         service.",
                    ),
                );
                self.note_unprotected_reject(ev.t_us);
            }
            _ => {}
        }
    }

    fn observe_nr_rrc(&mut self, ev: &AirEvent, m: &NrRrcMessage) {
        match m {
            NrRrcMessage::SystemInformation {
                plmn, tac, cell_id, ..
            } => {
                // 5G TAC is 24-bit: 0x000000 and 0xFFFFFE are reserved, 0xFFFFFF is
                // the "not assigned" value. The NR cell id (NCI) is 36-bit, so a
                // value at or beyond the 36-bit maximum is implausible.
                let reserved = *tac == 0x00_0000
                    || *tac == 0xFF_FFFE
                    || *tac == 0xFF_FFFF
                    || *cell_id >= 0xF_FFFF_FFFF;
                self.check_system_information(ev, *plmn, *tac as u64, *cell_id, reserved);
            }
            NrRrcMessage::Reject { .. } if !self.protected_context => {
                self.record(
                    FindingKind::UnprotectedReject,
                    Severity::High,
                    ev.t_us,
                    String::from(
                        "Unprotected 5G RRC Reject before any security context — a spoofable \
                         back-off that denies the UE its connection.",
                    ),
                );
                self.note_unprotected_reject(ev.t_us);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ocr_air::{AirEvent, CellId, Direction, Payload, Rat};
    use ocr_crypto::suci::{HomeNetworkKeyPair, ProtectionScheme};
    use ocr_crypto::SeededRng;
    use ocr_gsm::GsmMessage;
    use ocr_identity::{Plmn, Suci, Supi};
    use ocr_lte::{LteNasMessage, LteRrcMessage, NasAlgorithm};
    use ocr_nr::{
        AuthFailureCause, AuthenticationFailure, NrAlgorithm, NrNasMessage, NrRrcMessage,
    };

    fn plmn() -> Plmn {
        Plmn::new(262, 1, 2)
    }

    fn ev(t_us: u64, rat: Rat, cell: u32, payload: Payload) -> AirEvent {
        AirEvent {
            t_us,
            rat,
            cell: CellId(cell),
            dir: Direction::Observed,
            payload,
        }
    }

    fn gsm(t_us: u64, cell: u32, m: GsmMessage) -> AirEvent {
        ev(t_us, Rat::Gsm, cell, Payload::Gsm(m))
    }
    fn lte_nas(t_us: u64, cell: u32, m: LteNasMessage) -> AirEvent {
        ev(t_us, Rat::Lte, cell, Payload::LteNas(m))
    }
    fn lte_rrc(t_us: u64, cell: u32, m: LteRrcMessage) -> AirEvent {
        ev(t_us, Rat::Lte, cell, Payload::LteRrc(m))
    }
    fn nr_nas(t_us: u64, cell: u32, m: NrNasMessage) -> AirEvent {
        ev(t_us, Rat::Nr, cell, Payload::NrNas(m))
    }
    fn nr_rrc(t_us: u64, cell: u32, m: NrRrcMessage) -> AirEvent {
        ev(t_us, Rat::Nr, cell, Payload::NrRrc(m))
    }

    fn kinds(mon: &Monitor) -> Vec<FindingKind> {
        mon.findings().iter().map(|f| f.kind).collect()
    }

    fn has(mon: &Monitor, kind: FindingKind, sev: Severity) -> bool {
        mon.findings()
            .iter()
            .any(|f| f.kind == kind && f.severity == sev)
    }

    fn null_suci() -> Suci {
        let mut rng = SeededRng::new(1);
        let home = HomeNetworkKeyPair::generate(&mut rng);
        let supi = Supi::parse("262010123456789").unwrap();
        Suci::conceal(&supi, &home, ProtectionScheme::Null, 0, &mut rng)
    }

    fn protected_suci() -> Suci {
        let mut rng = SeededRng::new(2);
        let home = HomeNetworkKeyPair::generate(&mut rng);
        let supi = Supi::parse_with_mnc_len("310260123456789", 3).unwrap();
        Suci::conceal(&supi, &home, ProtectionScheme::ProfileA, 7, &mut rng)
    }

    // ---- negative / clean-air tests -----------------------------------------

    /// A normal, authenticated LTE attach by a returning subscriber (valid GUTI,
    /// real cipher) must raise NOTHING.
    #[test]
    fn clean_lte_attach_raises_nothing() {
        let mut mon = Monitor::new();
        mon.observe_all(&[
            lte_rrc(
                0,
                10,
                LteRrcMessage::SystemInformation {
                    plmn: Plmn::new(310, 260, 3),
                    tac: 0x1234,
                    cell_id: 0x0012_3456,
                },
            ),
            lte_nas(1, 10, LteNasMessage::AttachRequest { guti: None }),
            lte_nas(
                2,
                10,
                LteNasMessage::AuthenticationRequest {
                    rand: [0u8; 16],
                    autn: [0u8; 16],
                },
            ),
            lte_nas(
                3,
                10,
                LteNasMessage::AuthenticationResponse {
                    res: vec![1, 2, 3, 4],
                },
            ),
            lte_nas(
                4,
                10,
                LteNasMessage::SecurityModeCommand {
                    algorithm: NasAlgorithm::EEA2_EIA2,
                },
            ),
            lte_nas(5, 10, LteNasMessage::SecurityModeComplete),
            lte_nas(6, 10, LteNasMessage::AttachAccept { guti: None }),
        ]);
        assert!(
            mon.findings().is_empty(),
            "clean attach should raise nothing, got {:?}",
            kinds(&mon)
        );
    }

    /// A normal, authenticated GSM location update with a real cipher and a known
    /// TMSI (so no identity request) must raise NOTHING.
    #[test]
    fn clean_gsm_attach_raises_nothing() {
        use ocr_identity::Tmsi;
        let mut mon = Monitor::new();
        mon.observe_all(&[
            gsm(
                0,
                20,
                GsmMessage::SystemInformation {
                    plmn: plmn(),
                    lac: 0x00A1,
                    cell_id: 0x0042,
                },
            ),
            gsm(
                1,
                20,
                GsmMessage::LocationUpdateRequest {
                    tmsi: Some(Tmsi(1)),
                },
            ),
            gsm(2, 20, GsmMessage::AuthenticationRequest { rand: [0u8; 16] }),
            gsm(3, 20, GsmMessage::AuthenticationResponse { sres: [0u8; 4] }),
            gsm(
                4,
                20,
                GsmMessage::CipherModeCommand {
                    algorithm: A5::A5_1,
                },
            ),
            gsm(5, 20, GsmMessage::CipherModeComplete),
            gsm(
                6,
                20,
                GsmMessage::LocationUpdateAccept {
                    tmsi: Some(Tmsi(2)),
                },
            ),
        ]);
        assert!(
            mon.findings().is_empty(),
            "clean GSM attach should raise nothing, got {:?}",
            kinds(&mon)
        );
    }

    /// A protected (Profile A) SUCI registration that completes must raise NOTHING —
    /// the 5G fix, working.
    #[test]
    fn clean_nr_registration_raises_nothing() {
        let mut mon = Monitor::new();
        mon.observe_all(&[
            nr_rrc(
                0,
                30,
                NrRrcMessage::SystemInformation {
                    plmn: Plmn::new(310, 260, 3),
                    tac: 0x00_1234,
                    cell_id: 0x1_2345_6789,
                    allows_downgrade: false,
                },
            ),
            nr_nas(
                1,
                30,
                NrNasMessage::RegistrationRequest {
                    suci: Some(protected_suci()),
                    guti: None,
                },
            ),
            nr_nas(
                2,
                30,
                NrNasMessage::AuthenticationRequest {
                    rand: [0u8; 16],
                    autn: [0u8; 16],
                },
            ),
            nr_nas(
                3,
                30,
                NrNasMessage::AuthenticationResponse {
                    res_star: vec![9; 16],
                },
            ),
            nr_nas(
                4,
                30,
                NrNasMessage::SecurityModeCommand {
                    algorithm: NrAlgorithm::NEA2_NIA2,
                },
            ),
            nr_nas(5, 30, NrNasMessage::SecurityModeComplete),
            nr_nas(6, 30, NrNasMessage::RegistrationAccept { guti: None }),
        ]);
        assert!(
            mon.findings().is_empty(),
            "clean NR registration should raise nothing, got {:?}",
            kinds(&mon)
        );
    }

    // ---- positive, one per heuristic ----------------------------------------

    #[test]
    fn gsm_cleartext_imsi_request_is_high() {
        let mut mon = Monitor::new();
        mon.observe_all(&[
            gsm(
                0,
                1,
                GsmMessage::SystemInformation {
                    plmn: plmn(),
                    lac: 1,
                    cell_id: 1,
                },
            ),
            gsm(
                1,
                1,
                GsmMessage::IdentityRequest {
                    id_type: IdentityType::Imsi,
                },
            ),
        ]);
        assert!(has(
            &mon,
            FindingKind::CleartextIdentityRequest,
            Severity::High
        ));
    }

    #[test]
    fn gsm_tmsi_request_is_not_flagged() {
        // Only the *permanent* identity request is the catcher lever.
        let mut mon = Monitor::new();
        mon.observe(&gsm(
            0,
            1,
            GsmMessage::IdentityRequest {
                id_type: IdentityType::Tmsi,
            },
        ));
        assert!(mon.findings().is_empty());
    }

    #[test]
    fn lte_cleartext_identity_request_is_high() {
        let mut mon = Monitor::new();
        mon.observe(&lte_nas(0, 1, LteNasMessage::IdentityRequest));
        assert!(has(
            &mon,
            FindingKind::CleartextIdentityRequest,
            Severity::High
        ));
    }

    #[test]
    fn null_cipher_is_high_in_each_generation() {
        let mut g = Monitor::new();
        g.observe(&gsm(
            0,
            1,
            GsmMessage::CipherModeCommand {
                algorithm: A5::A5_0,
            },
        ));
        assert!(has(&g, FindingKind::NullCipherCommanded, Severity::High));

        let mut l = Monitor::new();
        l.observe(&lte_nas(
            0,
            1,
            LteNasMessage::SecurityModeCommand {
                algorithm: NasAlgorithm::EEA0_EIA0,
            },
        ));
        assert!(has(&l, FindingKind::NullCipherCommanded, Severity::High));

        let mut n = Monitor::new();
        n.observe(&nr_nas(
            0,
            1,
            NrNasMessage::SecurityModeCommand {
                algorithm: NrAlgorithm::NEA0_NIA0,
            },
        ));
        assert!(has(&n, FindingKind::NullCipherCommanded, Severity::High));
    }

    #[test]
    fn rat_drop_to_gsm_is_high_downgrade() {
        let mut mon = Monitor::new();
        mon.observe_all(&[
            lte_rrc(
                0,
                1,
                LteRrcMessage::SystemInformation {
                    plmn: plmn(),
                    tac: 5,
                    cell_id: 5,
                },
            ),
            gsm(
                1,
                2,
                GsmMessage::SystemInformation {
                    plmn: plmn(),
                    lac: 5,
                    cell_id: 5,
                },
            ),
        ]);
        assert!(has(&mon, FindingKind::ForcedDowngrade, Severity::High));
    }

    #[test]
    fn rat_drop_nr_to_lte_is_medium_downgrade() {
        let mut mon = Monitor::new();
        mon.observe_all(&[
            nr_rrc(
                0,
                1,
                NrRrcMessage::SystemInformation {
                    plmn: plmn(),
                    tac: 5,
                    cell_id: 5,
                    allows_downgrade: true,
                },
            ),
            lte_rrc(
                1,
                2,
                LteRrcMessage::SystemInformation {
                    plmn: plmn(),
                    tac: 5,
                    cell_id: 5,
                },
            ),
        ]);
        assert!(has(&mon, FindingKind::ForcedDowngrade, Severity::Medium));
    }

    #[test]
    fn reserved_tac_is_unexpected_identity() {
        let mut mon = Monitor::new();
        mon.observe(&lte_rrc(
            0,
            1,
            LteRrcMessage::SystemInformation {
                plmn: plmn(),
                tac: 0xFFFF,
                cell_id: 1,
            },
        ));
        assert!(has(
            &mon,
            FindingKind::UnexpectedCellIdentity,
            Severity::Medium
        ));
    }

    #[test]
    fn same_cell_changing_lac_is_location_area_jumped() {
        let mut mon = Monitor::new();
        mon.observe_all(&[
            gsm(
                0,
                7,
                GsmMessage::SystemInformation {
                    plmn: plmn(),
                    lac: 100,
                    cell_id: 9,
                },
            ),
            // Same opaque cell (7), same PLMN, different LAC: identity instability.
            gsm(
                1,
                7,
                GsmMessage::SystemInformation {
                    plmn: plmn(),
                    lac: 999,
                    cell_id: 9,
                },
            ),
        ]);
        assert!(has(&mon, FindingKind::LocationAreaJumped, Severity::Medium));
    }

    #[test]
    fn different_cells_with_different_lac_is_not_flagged() {
        // Ordinary reselection between two real cells must not cry wolf.
        let mut mon = Monitor::new();
        mon.observe_all(&[
            gsm(
                0,
                1,
                GsmMessage::SystemInformation {
                    plmn: plmn(),
                    lac: 100,
                    cell_id: 1,
                },
            ),
            gsm(
                1,
                2,
                GsmMessage::SystemInformation {
                    plmn: plmn(),
                    lac: 200,
                    cell_id: 2,
                },
            ),
        ]);
        assert!(
            mon.findings().is_empty(),
            "reselection between real cells should not flag, got {:?}",
            kinds(&mon)
        );
    }

    #[test]
    fn auth_started_then_reselect_is_never_completed() {
        let mut mon = Monitor::new();
        mon.observe_all(&[
            lte_rrc(
                0,
                1,
                LteRrcMessage::SystemInformation {
                    plmn: plmn(),
                    tac: 5,
                    cell_id: 5,
                },
            ),
            lte_nas(
                1,
                1,
                LteNasMessage::AuthenticationRequest {
                    rand: [0u8; 16],
                    autn: [0u8; 16],
                },
            ),
            // Reselect to a different LTE cell without ever completing security.
            lte_rrc(
                2,
                2,
                LteRrcMessage::SystemInformation {
                    plmn: plmn(),
                    tac: 6,
                    cell_id: 6,
                },
            ),
        ]);
        assert!(has(
            &mon,
            FindingKind::AuthenticationNeverCompleted,
            Severity::Medium
        ));
    }

    #[test]
    fn mac_failure_is_network_authentication_failed_high() {
        let mut l = Monitor::new();
        l.observe(&lte_nas(
            0,
            1,
            LteNasMessage::AuthenticationFailureMacFailure,
        ));
        assert!(has(
            &l,
            FindingKind::NetworkAuthenticationFailed,
            Severity::High
        ));

        let mut n = Monitor::new();
        n.observe(&nr_nas(
            0,
            1,
            NrNasMessage::AuthenticationFailure {
                cause: AuthFailureCause::MacFailure,
                auts: None,
            },
        ));
        assert!(has(
            &n,
            FindingKind::NetworkAuthenticationFailed,
            Severity::High
        ));
    }

    #[test]
    fn null_suci_in_registration_is_high() {
        let mut mon = Monitor::new();
        mon.observe(&nr_nas(
            0,
            1,
            NrNasMessage::RegistrationRequest {
                suci: Some(null_suci()),
                guti: None,
            },
        ));
        assert!(has(&mon, FindingKind::NullSuciScheme, Severity::High));
    }

    #[test]
    fn null_suci_in_identity_response_is_high() {
        let mut mon = Monitor::new();
        mon.observe(&nr_nas(
            0,
            1,
            NrNasMessage::IdentityResponseSuci { suci: null_suci() },
        ));
        assert!(has(&mon, FindingKind::NullSuciScheme, Severity::High));
    }

    #[test]
    fn protected_suci_registration_is_silent() {
        let mut mon = Monitor::new();
        mon.observe(&nr_nas(
            0,
            1,
            NrNasMessage::RegistrationRequest {
                suci: Some(protected_suci()),
                guti: None,
            },
        ));
        assert!(mon.findings().is_empty());
    }

    #[test]
    fn unprotected_attach_reject_is_high() {
        let mut mon = Monitor::new();
        mon.observe(&lte_nas(0, 1, LteNasMessage::AttachReject { cause: 15 }));
        assert!(has(&mon, FindingKind::UnprotectedReject, Severity::High));
    }

    #[test]
    fn reject_after_protected_context_is_not_flagged() {
        // Once integrity protection is up, a reject is trustworthy, not a lever.
        let mut mon = Monitor::new();
        mon.observe_all(&[
            lte_rrc(
                0,
                1,
                LteRrcMessage::SystemInformation {
                    plmn: plmn(),
                    tac: 5,
                    cell_id: 5,
                },
            ),
            lte_nas(
                1,
                1,
                LteNasMessage::SecurityModeCommand {
                    algorithm: NasAlgorithm::EEA2_EIA2,
                },
            ),
            lte_nas(2, 1, LteNasMessage::SecurityModeComplete),
            lte_nas(3, 1, LteNasMessage::TrackingAreaUpdateReject { cause: 9 }),
        ]);
        assert!(
            !mon.findings()
                .iter()
                .any(|f| f.kind == FindingKind::UnprotectedReject),
            "a protected reject must not be flagged, got {:?}",
            kinds(&mon)
        );
    }

    #[test]
    fn three_rejects_in_window_are_a_storm() {
        let mut mon = Monitor::new();
        mon.observe_all(&[
            lte_rrc(0, 1, LteRrcMessage::ConnectionReject { wait_time: 1 }),
            lte_rrc(100, 2, LteRrcMessage::ConnectionReject { wait_time: 1 }),
            lte_rrc(200, 3, LteRrcMessage::ConnectionReject { wait_time: 1 }),
        ]);
        assert!(has(&mon, FindingKind::RejectStorm, Severity::Medium));
    }

    #[test]
    fn imsi_paging_is_medium() {
        let mut mon = Monitor::new();
        mon.observe(&lte_nas(0, 1, LteNasMessage::Paging { by_imsi: true }));
        assert!(has(&mon, FindingKind::ImsiPaging, Severity::Medium));
    }

    #[test]
    fn tmsi_paging_is_not_flagged() {
        let mut mon = Monitor::new();
        mon.observe(&lte_nas(0, 1, LteNasMessage::Paging { by_imsi: false }));
        assert!(mon.findings().is_empty());
    }

    #[test]
    fn mixed_auth_failures_are_a_linkability_probe() {
        // Reference AuthenticationFailure so the frozen type is exercised here too.
        let _sanity = AuthenticationFailure {
            cause: AuthFailureCause::SynchFailure,
            auts: Some(vec![0u8; 14]),
        };
        let mut mon = Monitor::new();
        mon.observe_all(&[
            nr_nas(
                0,
                1,
                NrNasMessage::AuthenticationFailure {
                    cause: AuthFailureCause::MacFailure,
                    auts: None,
                },
            ),
            nr_nas(
                1,
                1,
                NrNasMessage::AuthenticationFailure {
                    cause: AuthFailureCause::SynchFailure,
                    auts: Some(vec![0u8; 14]),
                },
            ),
        ]);
        assert!(has(&mon, FindingKind::LinkabilityProbe, Severity::Low));
    }

    #[test]
    fn findingkind_display_is_stable() {
        assert_eq!(FindingKind::NullSuciScheme.as_str(), "Null SUCI scheme");
        // Display and as_str agree.
        assert_eq!(
            alloc::format!("{}", FindingKind::ForcedDowngrade),
            "Forced downgrade"
        );
    }
}
