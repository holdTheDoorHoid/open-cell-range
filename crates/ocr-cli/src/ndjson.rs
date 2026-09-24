//! The NDJSON capture format from `DESIGN.md` section 3 — the phase-two seam.
//!
//! One JSON object per line. `t_us`, `rat`, `dir`, `cell` and `msg` follow the
//! design doc's field shape exactly (`rat` is mandatory and authoritative;
//! `msg` is a human-readable decoded-message label). `ocr_air::AirEvent` and
//! its `Payload` union deliberately do **not** derive `serde` (the engines stay
//! `no_std`, and a real capture's raw-byte decoding is future importer work),
//! so this module defines a LOCAL mirror of exactly the message shapes this
//! simulator's engines can emit, and converts `AirEvent <-> WireEvent`
//! losslessly via the `payload` field.
//!
//! This is deliberately *not* the DESIGN.md `bytes`/`chan`/`arfcn` shape a real
//! hardware capture would carry — there is no raw byte encoding here because
//! nothing in this crate ever decodes raw bytes; every message the simulator
//! produces is already a decoded struct. Decoding an EXTERNAL capture
//! (Rayhunter's own output, SCAT, QCSuper, GSMTAP pcap) into this shape is
//! exactly the phase-two future work `DESIGN.md` defers; today `ocr replay`
//! only understands what `ocr record` wrote, which is enough to prove the
//! capture seam round-trips through the same `ocr_detect::Monitor` the browser
//! runs.
//!
//! `msg` is written for a human (or a future external reader) but is never
//! read back by [`from_line`] / [`read_events`] — `payload` is authoritative,
//! mirroring the design note that a reader falls back from `msg` to decoding
//! the structured content when it doesn't recognise the label.

use std::io::{self, BufRead, Write};

use ocr_air::{AirEvent, CellId, Direction, Payload, Rat};
use ocr_crypto::suci::{Concealed, ProtectionScheme};
use ocr_gsm::{GsmMessage, IdentityType, A5};
use ocr_identity::{FiveGGuti, Guti, Imsi, Plmn, Suci, Tmsi};
use ocr_lte::{LteNasMessage, LteRrcMessage, NasAlgorithm};
use ocr_nr::{AuthFailureCause, NrAlgorithm, NrNasMessage, NrRrcMessage};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Something went wrong reading or writing an NDJSON capture.
#[derive(Debug)]
pub enum NdjsonError {
    /// The line was not valid JSON, or not the shape [`WireEvent`] expects.
    Json(serde_json::Error),
    /// The underlying file/stream could not be read or written.
    Io(io::Error),
    /// A field that must be exactly `expected` bytes (a fixed-width crypto
    /// value like `rand`/`autn`) was a different length.
    BadLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
}

impl core::fmt::Display for NdjsonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NdjsonError::Json(e) => write!(f, "invalid NDJSON: {e}"),
            NdjsonError::Io(e) => write!(f, "I/O error: {e}"),
            NdjsonError::BadLength {
                field,
                expected,
                got,
            } => write!(f, "field `{field}` must be {expected} bytes, got {got}"),
        }
    }
}

impl std::error::Error for NdjsonError {}

impl From<serde_json::Error> for NdjsonError {
    fn from(e: serde_json::Error) -> Self {
        NdjsonError::Json(e)
    }
}

impl From<io::Error> for NdjsonError {
    fn from(e: io::Error) -> Self {
        NdjsonError::Io(e)
    }
}

fn fixed_bytes<const N: usize>(v: Vec<u8>, field: &'static str) -> Result<[u8; N], NdjsonError> {
    let got = v.len();
    v.try_into().map_err(|_| NdjsonError::BadLength {
        field,
        expected: N,
        got,
    })
}

// ---------------------------------------------------------------------------
// Shared identity mirrors
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WireRat {
    Gsm,
    Lte,
    Nr,
}

impl From<Rat> for WireRat {
    fn from(r: Rat) -> Self {
        match r {
            Rat::Gsm => WireRat::Gsm,
            Rat::Lte => WireRat::Lte,
            Rat::Nr => WireRat::Nr,
        }
    }
}

impl From<WireRat> for Rat {
    fn from(r: WireRat) -> Self {
        match r {
            WireRat::Gsm => Rat::Gsm,
            WireRat::Lte => Rat::Lte,
            WireRat::Nr => Rat::Nr,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WireDir {
    NetToUe,
    UeToNet,
    Observed,
}

impl From<Direction> for WireDir {
    fn from(d: Direction) -> Self {
        match d {
            Direction::NetToUe => WireDir::NetToUe,
            Direction::UeToNet => WireDir::UeToNet,
            Direction::Observed => WireDir::Observed,
        }
    }
}

impl From<WireDir> for Direction {
    fn from(d: WireDir) -> Self {
        match d {
            WireDir::NetToUe => Direction::NetToUe,
            WireDir::UeToNet => Direction::UeToNet,
            WireDir::Observed => Direction::Observed,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct WirePlmn {
    pub mcc: u16,
    pub mnc: u16,
    pub mnc_len: u8,
}

impl From<Plmn> for WirePlmn {
    fn from(p: Plmn) -> Self {
        WirePlmn {
            mcc: p.mcc,
            mnc: p.mnc,
            mnc_len: p.mnc_len,
        }
    }
}

impl From<WirePlmn> for Plmn {
    fn from(p: WirePlmn) -> Self {
        Plmn::new(p.mcc, p.mnc, p.mnc_len)
    }
}

/// Mirror of [`Imsi`] (PLMN + digit-per-byte MSIN). The permanent 5G identity
/// ([`ocr_identity::Supi`]) never itself appears in a `Payload` — only its
/// concealed [`Suci`] form ever crosses the air — so there is no `WireSupi`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WireMsin {
    pub plmn: WirePlmn,
    pub msin: Vec<u8>,
}

fn imsi_to_wire(i: &Imsi) -> WireMsin {
    WireMsin {
        plmn: i.plmn.into(),
        msin: i.msin.clone(),
    }
}

fn wire_to_imsi(w: WireMsin) -> Imsi {
    Imsi {
        plmn: w.plmn.into(),
        msin: w.msin,
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireGuti {
    pub plmn: WirePlmn,
    pub mme_group_id: u16,
    pub mme_code: u8,
    pub m_tmsi: u32,
}

impl From<Guti> for WireGuti {
    fn from(g: Guti) -> Self {
        WireGuti {
            plmn: g.plmn.into(),
            mme_group_id: g.mme_group_id,
            mme_code: g.mme_code,
            m_tmsi: g.m_tmsi,
        }
    }
}

impl From<WireGuti> for Guti {
    fn from(g: WireGuti) -> Self {
        Guti {
            plmn: g.plmn.into(),
            mme_group_id: g.mme_group_id,
            mme_code: g.mme_code,
            m_tmsi: g.m_tmsi,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireFiveGGuti {
    pub plmn: WirePlmn,
    pub amf_region_id: u8,
    pub amf_set_id: u16,
    pub amf_pointer: u8,
    pub tmsi: u32,
}

impl From<FiveGGuti> for WireFiveGGuti {
    fn from(g: FiveGGuti) -> Self {
        WireFiveGGuti {
            plmn: g.plmn.into(),
            amf_region_id: g.amf_region_id,
            amf_set_id: g.amf_set_id,
            amf_pointer: g.amf_pointer,
            tmsi: g.tmsi,
        }
    }
}

impl From<WireFiveGGuti> for FiveGGuti {
    fn from(g: WireFiveGGuti) -> Self {
        FiveGGuti {
            plmn: g.plmn.into(),
            amf_region_id: g.amf_region_id,
            amf_set_id: g.amf_set_id,
            amf_pointer: g.amf_pointer,
            tmsi: g.tmsi,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireProtectionScheme {
    Null,
    ProfileA,
}

impl From<ProtectionScheme> for WireProtectionScheme {
    fn from(s: ProtectionScheme) -> Self {
        match s {
            ProtectionScheme::Null => WireProtectionScheme::Null,
            ProtectionScheme::ProfileA => WireProtectionScheme::ProfileA,
        }
    }
}

impl From<WireProtectionScheme> for ProtectionScheme {
    fn from(s: WireProtectionScheme) -> Self {
        match s {
            WireProtectionScheme::Null => ProtectionScheme::Null,
            WireProtectionScheme::ProfileA => ProtectionScheme::ProfileA,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WireConcealed {
    pub scheme: WireProtectionScheme,
    pub eph_public_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub mac: Vec<u8>,
}

fn concealed_to_wire(c: &Concealed) -> WireConcealed {
    WireConcealed {
        scheme: c.scheme.into(),
        eph_public_key: c.eph_public_key.clone(),
        ciphertext: c.ciphertext.clone(),
        mac: c.mac.clone(),
    }
}

fn wire_to_concealed(w: WireConcealed) -> Concealed {
    Concealed {
        scheme: w.scheme.into(),
        eph_public_key: w.eph_public_key,
        ciphertext: w.ciphertext,
        mac: w.mac,
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WireSuci {
    pub plmn: WirePlmn,
    pub routing_indicator: u16,
    pub scheme: WireProtectionScheme,
    pub concealed: WireConcealed,
}

fn suci_to_wire(s: &Suci) -> WireSuci {
    WireSuci {
        plmn: s.plmn.into(),
        routing_indicator: s.routing_indicator,
        scheme: s.scheme.into(),
        concealed: concealed_to_wire(&s.concealed),
    }
}

fn wire_to_suci(w: WireSuci) -> Suci {
    Suci {
        plmn: w.plmn.into(),
        routing_indicator: w.routing_indicator,
        scheme: w.scheme.into(),
        concealed: wire_to_concealed(w.concealed),
    }
}

// ---------------------------------------------------------------------------
// Per-generation algorithm / identity-type mirrors
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum WireA5 {
    A5_0,
    A5_1,
    A5_3,
}

impl From<A5> for WireA5 {
    fn from(a: A5) -> Self {
        match a {
            A5::A5_0 => WireA5::A5_0,
            A5::A5_1 => WireA5::A5_1,
            A5::A5_3 => WireA5::A5_3,
        }
    }
}

impl From<WireA5> for A5 {
    fn from(a: WireA5) -> Self {
        match a {
            WireA5::A5_0 => A5::A5_0,
            WireA5::A5_1 => A5::A5_1,
            WireA5::A5_3 => A5::A5_3,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireIdentityType {
    Imsi,
    Tmsi,
    Imei,
}

impl From<IdentityType> for WireIdentityType {
    fn from(t: IdentityType) -> Self {
        match t {
            IdentityType::Imsi => WireIdentityType::Imsi,
            IdentityType::Tmsi => WireIdentityType::Tmsi,
            IdentityType::Imei => WireIdentityType::Imei,
        }
    }
}

impl From<WireIdentityType> for IdentityType {
    fn from(t: WireIdentityType) -> Self {
        match t {
            WireIdentityType::Imsi => IdentityType::Imsi,
            WireIdentityType::Tmsi => IdentityType::Tmsi,
            WireIdentityType::Imei => IdentityType::Imei,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum WireNasAlgorithm {
    EEA0_EIA0,
    EEA1_EIA1,
    EEA2_EIA2,
}

impl From<NasAlgorithm> for WireNasAlgorithm {
    fn from(a: NasAlgorithm) -> Self {
        match a {
            NasAlgorithm::EEA0_EIA0 => WireNasAlgorithm::EEA0_EIA0,
            NasAlgorithm::EEA1_EIA1 => WireNasAlgorithm::EEA1_EIA1,
            NasAlgorithm::EEA2_EIA2 => WireNasAlgorithm::EEA2_EIA2,
        }
    }
}

impl From<WireNasAlgorithm> for NasAlgorithm {
    fn from(a: WireNasAlgorithm) -> Self {
        match a {
            WireNasAlgorithm::EEA0_EIA0 => NasAlgorithm::EEA0_EIA0,
            WireNasAlgorithm::EEA1_EIA1 => NasAlgorithm::EEA1_EIA1,
            WireNasAlgorithm::EEA2_EIA2 => NasAlgorithm::EEA2_EIA2,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum WireNrAlgorithm {
    NEA0_NIA0,
    NEA1_NIA1,
    NEA2_NIA2,
}

impl From<NrAlgorithm> for WireNrAlgorithm {
    fn from(a: NrAlgorithm) -> Self {
        match a {
            NrAlgorithm::NEA0_NIA0 => WireNrAlgorithm::NEA0_NIA0,
            NrAlgorithm::NEA1_NIA1 => WireNrAlgorithm::NEA1_NIA1,
            NrAlgorithm::NEA2_NIA2 => WireNrAlgorithm::NEA2_NIA2,
        }
    }
}

impl From<WireNrAlgorithm> for NrAlgorithm {
    fn from(a: WireNrAlgorithm) -> Self {
        match a {
            WireNrAlgorithm::NEA0_NIA0 => NrAlgorithm::NEA0_NIA0,
            WireNrAlgorithm::NEA1_NIA1 => NrAlgorithm::NEA1_NIA1,
            WireNrAlgorithm::NEA2_NIA2 => NrAlgorithm::NEA2_NIA2,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireAuthFailureCause {
    MacFailure,
    SynchFailure,
}

impl From<AuthFailureCause> for WireAuthFailureCause {
    fn from(c: AuthFailureCause) -> Self {
        match c {
            AuthFailureCause::MacFailure => WireAuthFailureCause::MacFailure,
            AuthFailureCause::SynchFailure => WireAuthFailureCause::SynchFailure,
        }
    }
}

impl From<WireAuthFailureCause> for AuthFailureCause {
    fn from(c: WireAuthFailureCause) -> Self {
        match c {
            WireAuthFailureCause::MacFailure => AuthFailureCause::MacFailure,
            WireAuthFailureCause::SynchFailure => AuthFailureCause::SynchFailure,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-generation message mirrors
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum WireGsmMessage {
    SystemInformation {
        plmn: WirePlmn,
        lac: u16,
        cell_id: u16,
    },
    LocationUpdateRequest {
        tmsi: Option<u32>,
    },
    IdentityRequest {
        id_type: WireIdentityType,
    },
    IdentityResponse {
        imsi: Option<WireMsin>,
    },
    AuthenticationRequest {
        rand: Vec<u8>,
    },
    AuthenticationResponse {
        sres: Vec<u8>,
    },
    CipherModeCommand {
        algorithm: WireA5,
    },
    CipherModeComplete,
    LocationUpdateAccept {
        tmsi: Option<u32>,
    },
    LocationUpdateReject {
        cause: u8,
    },
}

fn gsm_to_wire(m: &GsmMessage) -> WireGsmMessage {
    match m {
        GsmMessage::SystemInformation { plmn, lac, cell_id } => WireGsmMessage::SystemInformation {
            plmn: (*plmn).into(),
            lac: *lac,
            cell_id: *cell_id,
        },
        GsmMessage::LocationUpdateRequest { tmsi } => WireGsmMessage::LocationUpdateRequest {
            tmsi: tmsi.map(|t| t.0),
        },
        GsmMessage::IdentityRequest { id_type } => WireGsmMessage::IdentityRequest {
            id_type: (*id_type).into(),
        },
        GsmMessage::IdentityResponse { imsi } => WireGsmMessage::IdentityResponse {
            imsi: imsi.as_ref().map(imsi_to_wire),
        },
        GsmMessage::AuthenticationRequest { rand } => WireGsmMessage::AuthenticationRequest {
            rand: rand.to_vec(),
        },
        GsmMessage::AuthenticationResponse { sres } => WireGsmMessage::AuthenticationResponse {
            sres: sres.to_vec(),
        },
        GsmMessage::CipherModeCommand { algorithm } => WireGsmMessage::CipherModeCommand {
            algorithm: (*algorithm).into(),
        },
        GsmMessage::CipherModeComplete => WireGsmMessage::CipherModeComplete,
        GsmMessage::LocationUpdateAccept { tmsi } => WireGsmMessage::LocationUpdateAccept {
            tmsi: tmsi.map(|t| t.0),
        },
        GsmMessage::LocationUpdateReject { cause } => {
            WireGsmMessage::LocationUpdateReject { cause: *cause }
        }
    }
}

fn wire_to_gsm(m: WireGsmMessage) -> Result<GsmMessage, NdjsonError> {
    Ok(match m {
        WireGsmMessage::SystemInformation { plmn, lac, cell_id } => GsmMessage::SystemInformation {
            plmn: plmn.into(),
            lac,
            cell_id,
        },
        WireGsmMessage::LocationUpdateRequest { tmsi } => GsmMessage::LocationUpdateRequest {
            tmsi: tmsi.map(Tmsi),
        },
        WireGsmMessage::IdentityRequest { id_type } => GsmMessage::IdentityRequest {
            id_type: id_type.into(),
        },
        WireGsmMessage::IdentityResponse { imsi } => GsmMessage::IdentityResponse {
            imsi: imsi.map(wire_to_imsi),
        },
        WireGsmMessage::AuthenticationRequest { rand } => GsmMessage::AuthenticationRequest {
            rand: fixed_bytes(rand, "gsm.AuthenticationRequest.rand")?,
        },
        WireGsmMessage::AuthenticationResponse { sres } => GsmMessage::AuthenticationResponse {
            sres: fixed_bytes(sres, "gsm.AuthenticationResponse.sres")?,
        },
        WireGsmMessage::CipherModeCommand { algorithm } => GsmMessage::CipherModeCommand {
            algorithm: algorithm.into(),
        },
        WireGsmMessage::CipherModeComplete => GsmMessage::CipherModeComplete,
        WireGsmMessage::LocationUpdateAccept { tmsi } => GsmMessage::LocationUpdateAccept {
            tmsi: tmsi.map(Tmsi),
        },
        WireGsmMessage::LocationUpdateReject { cause } => {
            GsmMessage::LocationUpdateReject { cause }
        }
    })
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum WireLteRrcMessage {
    SystemInformation {
        plmn: WirePlmn,
        tac: u16,
        cell_id: u32,
    },
    ConnectionRequest,
    ConnectionSetup,
    ConnectionReject {
        wait_time: u8,
    },
    MeasurementReport,
}

fn lte_rrc_to_wire(m: &LteRrcMessage) -> WireLteRrcMessage {
    match m {
        LteRrcMessage::SystemInformation { plmn, tac, cell_id } => {
            WireLteRrcMessage::SystemInformation {
                plmn: (*plmn).into(),
                tac: *tac,
                cell_id: *cell_id,
            }
        }
        LteRrcMessage::ConnectionRequest => WireLteRrcMessage::ConnectionRequest,
        LteRrcMessage::ConnectionSetup => WireLteRrcMessage::ConnectionSetup,
        LteRrcMessage::ConnectionReject { wait_time } => WireLteRrcMessage::ConnectionReject {
            wait_time: *wait_time,
        },
        LteRrcMessage::MeasurementReport => WireLteRrcMessage::MeasurementReport,
    }
}

fn wire_to_lte_rrc(m: WireLteRrcMessage) -> Result<LteRrcMessage, NdjsonError> {
    Ok(match m {
        WireLteRrcMessage::SystemInformation { plmn, tac, cell_id } => {
            LteRrcMessage::SystemInformation {
                plmn: plmn.into(),
                tac,
                cell_id,
            }
        }
        WireLteRrcMessage::ConnectionRequest => LteRrcMessage::ConnectionRequest,
        WireLteRrcMessage::ConnectionSetup => LteRrcMessage::ConnectionSetup,
        WireLteRrcMessage::ConnectionReject { wait_time } => {
            LteRrcMessage::ConnectionReject { wait_time }
        }
        WireLteRrcMessage::MeasurementReport => LteRrcMessage::MeasurementReport,
    })
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum WireLteNasMessage {
    AttachRequest { guti: Option<WireGuti> },
    IdentityRequest,
    IdentityResponse { imsi: Option<WireMsin> },
    AuthenticationRequest { rand: Vec<u8>, autn: Vec<u8> },
    AuthenticationResponse { res: Vec<u8> },
    AuthenticationFailureSyncFailure { auts: Vec<u8> },
    AuthenticationFailureMacFailure,
    SecurityModeCommand { algorithm: WireNasAlgorithm },
    SecurityModeComplete,
    AttachAccept { guti: Option<WireGuti> },
    AttachReject { cause: u8 },
    TrackingAreaUpdateReject { cause: u8 },
    Paging { by_imsi: bool },
}

fn lte_nas_to_wire(m: &LteNasMessage) -> WireLteNasMessage {
    match m {
        LteNasMessage::AttachRequest { guti } => WireLteNasMessage::AttachRequest {
            guti: guti.map(Into::into),
        },
        LteNasMessage::IdentityRequest => WireLteNasMessage::IdentityRequest,
        LteNasMessage::IdentityResponse { imsi } => WireLteNasMessage::IdentityResponse {
            imsi: imsi.as_ref().map(imsi_to_wire),
        },
        LteNasMessage::AuthenticationRequest { rand, autn } => {
            WireLteNasMessage::AuthenticationRequest {
                rand: rand.to_vec(),
                autn: autn.to_vec(),
            }
        }
        LteNasMessage::AuthenticationResponse { res } => {
            WireLteNasMessage::AuthenticationResponse { res: res.clone() }
        }
        LteNasMessage::AuthenticationFailureSyncFailure { auts } => {
            WireLteNasMessage::AuthenticationFailureSyncFailure { auts: auts.clone() }
        }
        LteNasMessage::AuthenticationFailureMacFailure => {
            WireLteNasMessage::AuthenticationFailureMacFailure
        }
        LteNasMessage::SecurityModeCommand { algorithm } => {
            WireLteNasMessage::SecurityModeCommand {
                algorithm: (*algorithm).into(),
            }
        }
        LteNasMessage::SecurityModeComplete => WireLteNasMessage::SecurityModeComplete,
        LteNasMessage::AttachAccept { guti } => WireLteNasMessage::AttachAccept {
            guti: guti.map(Into::into),
        },
        LteNasMessage::AttachReject { cause } => WireLteNasMessage::AttachReject { cause: *cause },
        LteNasMessage::TrackingAreaUpdateReject { cause } => {
            WireLteNasMessage::TrackingAreaUpdateReject { cause: *cause }
        }
        LteNasMessage::Paging { by_imsi } => WireLteNasMessage::Paging { by_imsi: *by_imsi },
    }
}

fn wire_to_lte_nas(m: WireLteNasMessage) -> Result<LteNasMessage, NdjsonError> {
    Ok(match m {
        WireLteNasMessage::AttachRequest { guti } => LteNasMessage::AttachRequest {
            guti: guti.map(Into::into),
        },
        WireLteNasMessage::IdentityRequest => LteNasMessage::IdentityRequest,
        WireLteNasMessage::IdentityResponse { imsi } => LteNasMessage::IdentityResponse {
            imsi: imsi.map(wire_to_imsi),
        },
        WireLteNasMessage::AuthenticationRequest { rand, autn } => {
            LteNasMessage::AuthenticationRequest {
                rand: fixed_bytes(rand, "lte_nas.AuthenticationRequest.rand")?,
                autn: fixed_bytes(autn, "lte_nas.AuthenticationRequest.autn")?,
            }
        }
        WireLteNasMessage::AuthenticationResponse { res } => {
            LteNasMessage::AuthenticationResponse { res }
        }
        WireLteNasMessage::AuthenticationFailureSyncFailure { auts } => {
            LteNasMessage::AuthenticationFailureSyncFailure { auts }
        }
        WireLteNasMessage::AuthenticationFailureMacFailure => {
            LteNasMessage::AuthenticationFailureMacFailure
        }
        WireLteNasMessage::SecurityModeCommand { algorithm } => {
            LteNasMessage::SecurityModeCommand {
                algorithm: algorithm.into(),
            }
        }
        WireLteNasMessage::SecurityModeComplete => LteNasMessage::SecurityModeComplete,
        WireLteNasMessage::AttachAccept { guti } => LteNasMessage::AttachAccept {
            guti: guti.map(Into::into),
        },
        WireLteNasMessage::AttachReject { cause } => LteNasMessage::AttachReject { cause },
        WireLteNasMessage::TrackingAreaUpdateReject { cause } => {
            LteNasMessage::TrackingAreaUpdateReject { cause }
        }
        WireLteNasMessage::Paging { by_imsi } => LteNasMessage::Paging { by_imsi },
    })
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum WireNrRrcMessage {
    SystemInformation {
        plmn: WirePlmn,
        tac: u32,
        cell_id: u64,
        allows_downgrade: bool,
    },
    SetupRequest,
    Setup,
    Reject {
        wait_time: u8,
    },
}

fn nr_rrc_to_wire(m: &NrRrcMessage) -> WireNrRrcMessage {
    match m {
        NrRrcMessage::SystemInformation {
            plmn,
            tac,
            cell_id,
            allows_downgrade,
        } => WireNrRrcMessage::SystemInformation {
            plmn: (*plmn).into(),
            tac: *tac,
            cell_id: *cell_id,
            allows_downgrade: *allows_downgrade,
        },
        NrRrcMessage::SetupRequest => WireNrRrcMessage::SetupRequest,
        NrRrcMessage::Setup => WireNrRrcMessage::Setup,
        NrRrcMessage::Reject { wait_time } => WireNrRrcMessage::Reject {
            wait_time: *wait_time,
        },
    }
}

fn wire_to_nr_rrc(m: WireNrRrcMessage) -> Result<NrRrcMessage, NdjsonError> {
    Ok(match m {
        WireNrRrcMessage::SystemInformation {
            plmn,
            tac,
            cell_id,
            allows_downgrade,
        } => NrRrcMessage::SystemInformation {
            plmn: plmn.into(),
            tac,
            cell_id,
            allows_downgrade,
        },
        WireNrRrcMessage::SetupRequest => NrRrcMessage::SetupRequest,
        WireNrRrcMessage::Setup => NrRrcMessage::Setup,
        WireNrRrcMessage::Reject { wait_time } => NrRrcMessage::Reject { wait_time },
    })
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum WireNrNasMessage {
    RegistrationRequest {
        suci: Option<WireSuci>,
        guti: Option<WireFiveGGuti>,
    },
    IdentityRequestSuci,
    IdentityResponseSuci {
        suci: WireSuci,
    },
    AuthenticationRequest {
        rand: Vec<u8>,
        autn: Vec<u8>,
    },
    AuthenticationResponse {
        res_star: Vec<u8>,
    },
    AuthenticationFailure {
        cause: WireAuthFailureCause,
        auts: Option<Vec<u8>>,
    },
    SecurityModeCommand {
        algorithm: WireNrAlgorithm,
    },
    SecurityModeComplete,
    RegistrationAccept {
        guti: Option<WireFiveGGuti>,
    },
    RegistrationReject {
        cause: u8,
    },
}

fn nr_nas_to_wire(m: &NrNasMessage) -> WireNrNasMessage {
    match m {
        NrNasMessage::RegistrationRequest { suci, guti } => WireNrNasMessage::RegistrationRequest {
            suci: suci.as_ref().map(suci_to_wire),
            guti: guti.map(Into::into),
        },
        NrNasMessage::IdentityRequestSuci => WireNrNasMessage::IdentityRequestSuci,
        NrNasMessage::IdentityResponseSuci { suci } => WireNrNasMessage::IdentityResponseSuci {
            suci: suci_to_wire(suci),
        },
        NrNasMessage::AuthenticationRequest { rand, autn } => {
            WireNrNasMessage::AuthenticationRequest {
                rand: rand.to_vec(),
                autn: autn.to_vec(),
            }
        }
        NrNasMessage::AuthenticationResponse { res_star } => {
            WireNrNasMessage::AuthenticationResponse {
                res_star: res_star.clone(),
            }
        }
        NrNasMessage::AuthenticationFailure { cause, auts } => {
            WireNrNasMessage::AuthenticationFailure {
                cause: (*cause).into(),
                auts: auts.clone(),
            }
        }
        NrNasMessage::SecurityModeCommand { algorithm } => WireNrNasMessage::SecurityModeCommand {
            algorithm: (*algorithm).into(),
        },
        NrNasMessage::SecurityModeComplete => WireNrNasMessage::SecurityModeComplete,
        NrNasMessage::RegistrationAccept { guti } => WireNrNasMessage::RegistrationAccept {
            guti: guti.map(Into::into),
        },
        NrNasMessage::RegistrationReject { cause } => {
            WireNrNasMessage::RegistrationReject { cause: *cause }
        }
    }
}

fn wire_to_nr_nas(m: WireNrNasMessage) -> Result<NrNasMessage, NdjsonError> {
    Ok(match m {
        WireNrNasMessage::RegistrationRequest { suci, guti } => NrNasMessage::RegistrationRequest {
            suci: suci.map(wire_to_suci),
            guti: guti.map(Into::into),
        },
        WireNrNasMessage::IdentityRequestSuci => NrNasMessage::IdentityRequestSuci,
        WireNrNasMessage::IdentityResponseSuci { suci } => NrNasMessage::IdentityResponseSuci {
            suci: wire_to_suci(suci),
        },
        WireNrNasMessage::AuthenticationRequest { rand, autn } => {
            NrNasMessage::AuthenticationRequest {
                rand: fixed_bytes(rand, "nr_nas.AuthenticationRequest.rand")?,
                autn: fixed_bytes(autn, "nr_nas.AuthenticationRequest.autn")?,
            }
        }
        WireNrNasMessage::AuthenticationResponse { res_star } => {
            NrNasMessage::AuthenticationResponse { res_star }
        }
        WireNrNasMessage::AuthenticationFailure { cause, auts } => {
            NrNasMessage::AuthenticationFailure {
                cause: cause.into(),
                auts,
            }
        }
        WireNrNasMessage::SecurityModeCommand { algorithm } => NrNasMessage::SecurityModeCommand {
            algorithm: algorithm.into(),
        },
        WireNrNasMessage::SecurityModeComplete => NrNasMessage::SecurityModeComplete,
        WireNrNasMessage::RegistrationAccept { guti } => NrNasMessage::RegistrationAccept {
            guti: guti.map(Into::into),
        },
        WireNrNasMessage::RegistrationReject { cause } => {
            NrNasMessage::RegistrationReject { cause }
        }
    })
}

// ---------------------------------------------------------------------------
// The whole payload union, and the event that carries it
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum WirePayload {
    Gsm(WireGsmMessage),
    LteNas(WireLteNasMessage),
    LteRrc(WireLteRrcMessage),
    NrNas(WireNrNasMessage),
    NrRrc(WireNrRrcMessage),
}

fn payload_to_wire(p: &Payload) -> WirePayload {
    match p {
        Payload::Gsm(m) => WirePayload::Gsm(gsm_to_wire(m)),
        Payload::LteNas(m) => WirePayload::LteNas(lte_nas_to_wire(m)),
        Payload::LteRrc(m) => WirePayload::LteRrc(lte_rrc_to_wire(m)),
        Payload::NrNas(m) => WirePayload::NrNas(nr_nas_to_wire(m)),
        Payload::NrRrc(m) => WirePayload::NrRrc(nr_rrc_to_wire(m)),
    }
}

fn wire_to_payload(p: WirePayload) -> Result<Payload, NdjsonError> {
    Ok(match p {
        WirePayload::Gsm(m) => Payload::Gsm(wire_to_gsm(m)?),
        WirePayload::LteNas(m) => Payload::LteNas(wire_to_lte_nas(m)?),
        WirePayload::LteRrc(m) => Payload::LteRrc(wire_to_lte_rrc(m)?),
        WirePayload::NrNas(m) => Payload::NrNas(wire_to_nr_nas(m)?),
        WirePayload::NrRrc(m) => Payload::NrRrc(wire_to_nr_rrc(m)?),
    })
}

/// One NDJSON line. `t_us` / `rat` / `dir` / `cell` / `msg` match `DESIGN.md`
/// section 3; `payload` is this crate's addition, carrying everything needed
/// to reconstruct the `AirEvent` exactly (see the module docs).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WireEvent {
    pub t_us: u64,
    pub rat: WireRat,
    pub dir: WireDir,
    pub cell: u32,
    pub msg: String,
    pub payload: WirePayload,
}

impl From<&AirEvent> for WireEvent {
    fn from(ev: &AirEvent) -> Self {
        WireEvent {
            t_us: ev.t_us,
            rat: ev.rat.into(),
            dir: ev.dir.into(),
            cell: ev.cell.0,
            msg: ocr_air::describe(ev),
            payload: payload_to_wire(&ev.payload),
        }
    }
}

impl TryFrom<WireEvent> for AirEvent {
    type Error = NdjsonError;

    fn try_from(w: WireEvent) -> Result<Self, Self::Error> {
        Ok(AirEvent {
            t_us: w.t_us,
            rat: w.rat.into(),
            cell: CellId(w.cell),
            dir: w.dir.into(),
            payload: wire_to_payload(w.payload)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Public line / stream API
// ---------------------------------------------------------------------------

/// Serialize one event to a single NDJSON line (no trailing newline).
pub fn to_line(ev: &AirEvent) -> Result<String, NdjsonError> {
    Ok(serde_json::to_string(&WireEvent::from(ev))?)
}

/// Parse one NDJSON line back into an `AirEvent`.
pub fn from_line(line: &str) -> Result<AirEvent, NdjsonError> {
    let wire: WireEvent = serde_json::from_str(line)?;
    wire.try_into()
}

/// Write a whole event stream as NDJSON, one line per event.
pub fn write_events<W: Write>(events: &[AirEvent], w: &mut W) -> Result<(), NdjsonError> {
    for ev in events {
        writeln!(w, "{}", to_line(ev)?)?;
    }
    Ok(())
}

/// Read a whole NDJSON stream back into events, in order. Blank lines are
/// skipped so a trailing newline in the file doesn't produce a parse error.
pub fn read_events<R: BufRead>(r: R) -> Result<Vec<AirEvent>, NdjsonError> {
    let mut events = Vec::new();
    for line in r.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        events.push(from_line(&line)?);
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ocr_detect::Monitor;
    use ocr_scenario::ScenarioId;

    fn finding_kinds(monitor: &Monitor) -> Vec<ocr_detect::FindingKind> {
        monitor.findings().iter().map(|f| f.kind).collect()
    }

    /// The headline round-trip proof: record every scenario's air to NDJSON,
    /// read it back, and the events must be byte-for-byte identical.
    #[test]
    fn round_trip_preserves_events_for_every_scenario() {
        for &id in ScenarioId::all() {
            let mut scenario = ocr_scenario::build(id);
            scenario.run_headline();
            let events = scenario.world.events();
            assert!(
                !events.is_empty(),
                "{id:?} produced no events to round-trip"
            );

            let mut buf = Vec::new();
            write_events(events, &mut buf).expect("write_events must not fail");
            let parsed = read_events(&buf[..]).expect("read_events must parse what we wrote");

            assert_eq!(
                events,
                &parsed[..],
                "{id:?} did not round-trip byte for byte"
            );
        }
    }

    /// The point of the seam: a monitor run over the replayed capture must
    /// raise exactly the same finding kinds as one run directly over the live
    /// world's events, for every scenario in the catalogue.
    #[test]
    fn round_trip_monitor_findings_match_direct_run() {
        for &id in ScenarioId::all() {
            let mut scenario = ocr_scenario::build(id);
            scenario.run_headline();
            let events = scenario.world.events();

            let mut direct = Monitor::new();
            direct.observe_all(events);

            let mut buf = Vec::new();
            write_events(events, &mut buf).unwrap();
            let replayed_events = read_events(&buf[..]).unwrap();
            let mut replayed = Monitor::new();
            replayed.observe_all(&replayed_events);

            assert_eq!(
                finding_kinds(&direct),
                finding_kinds(&replayed),
                "{id:?}: replayed capture raised different findings than the live run"
            );
        }
    }

    #[test]
    fn single_line_round_trips_a_hand_built_event() {
        let ev = AirEvent {
            t_us: 42,
            rat: Rat::Nr,
            cell: CellId(7),
            dir: Direction::Observed,
            payload: Payload::NrRrc(NrRrcMessage::SystemInformation {
                plmn: Plmn::new(310, 260, 3),
                tac: 0x1234,
                cell_id: 0x1_2345_6789,
                allows_downgrade: true,
            }),
        };
        let line = to_line(&ev).expect("serialize");
        assert!(line.contains("\"t_us\":42"));
        let back = from_line(&line).expect("parse");
        assert_eq!(back, ev);
    }

    #[test]
    fn read_events_rejects_malformed_json() {
        let bad = b"{ this is not json\n";
        assert!(read_events(&bad[..]).is_err());
    }

    #[test]
    fn read_events_rejects_wrong_length_fixed_arrays() {
        let line = serde_json::to_string(&WireEvent {
            t_us: 0,
            rat: WireRat::Gsm,
            dir: WireDir::Observed,
            cell: 1,
            msg: "bad rand length".into(),
            payload: WirePayload::Gsm(WireGsmMessage::AuthenticationRequest {
                rand: vec![1, 2, 3],
            }),
        })
        .unwrap();

        match from_line(&line) {
            Err(NdjsonError::BadLength {
                field,
                expected,
                got,
            }) => {
                assert_eq!(field, "gsm.AuthenticationRequest.rand");
                assert_eq!(expected, 16);
                assert_eq!(got, 3);
            }
            other => panic!("expected BadLength, got {other:?}"),
        }
    }

    #[test]
    fn read_events_skips_blank_lines() {
        let ev = AirEvent {
            t_us: 1,
            rat: Rat::Gsm,
            cell: CellId(1),
            dir: Direction::NetToUe,
            payload: Payload::Gsm(GsmMessage::CipherModeComplete),
        };
        let mut buf = Vec::new();
        write_events(std::slice::from_ref(&ev), &mut buf).unwrap();
        buf.extend_from_slice(b"\n\n");
        let parsed = read_events(&buf[..]).unwrap();
        assert_eq!(parsed, vec![ev]);
    }
}
