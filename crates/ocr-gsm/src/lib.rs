//! 2G / GSM model for Open Cell Range — the "broken by design" chapter.
//!
//! GSM authentication is one-way: the network challenges the phone, the phone
//! never challenges the network. Encryption is optional and the network picks it,
//! including [`A5::A5_0`] (none). Those two facts are every classic IMSI-catcher
//! attack, so they are modelled explicitly rather than assumed away.
//!
//! ## Implementer notes (stubbed; fill the bodies)
//! - `GsmAuthVector` derives from `ocr_crypto::Milenage` (2G interworking:
//!   `SRES = XRES[0..4] XOR XRES[4..8]`, `Kc = CK/IK folded`), or a documented
//!   simplification if you keep it self-contained — say which in a comment.
//! - Keep messages as decoded structs, not bytes; the NDJSON capture seam owns
//!   the byte form.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use ocr_identity::{Imsi, Plmn, Tmsi};

/// GSM ciphering algorithms. `A5_0` is null encryption — legal, and what a rogue
/// BTS commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum A5 {
    A5_0,
    A5_1,
    A5_3,
}

/// The identity a network can ask a phone to reveal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityType {
    Imsi,
    Tmsi,
    Imei,
}

/// A decoded GSM signalling message on the Um interface. Not exhaustive of the
/// spec — the subset the range teaches with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GsmMessage {
    /// Broadcast identity + selection parameters of a cell.
    SystemInformation {
        plmn: Plmn,
        lac: u16,
        cell_id: u16,
    },
    LocationUpdateRequest {
        tmsi: Option<Tmsi>,
    },
    /// The message that hands over the permanent identity in cleartext.
    IdentityRequest {
        id_type: IdentityType,
    },
    IdentityResponse {
        imsi: Option<Imsi>,
    },
    AuthenticationRequest {
        rand: [u8; 16],
    },
    AuthenticationResponse {
        sres: [u8; 4],
    },
    /// The network's choice of cipher — including `A5_0`.
    CipherModeCommand {
        algorithm: A5,
    },
    CipherModeComplete,
    LocationUpdateAccept {
        tmsi: Option<Tmsi>,
    },
    LocationUpdateReject {
        cause: u8,
    },
}

/// A 2G authentication triplet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GsmAuthVector {
    pub rand: [u8; 16],
    pub sres: [u8; 4],
    pub kc: [u8; 8],
}

/// Compute the expected `SRES`/`Kc` for a challenge, as the network does.
pub fn auth_vector(k: &[u8; 16], op_c: &[u8; 16], rand: &[u8; 16]) -> GsmAuthVector {
    let _ = (k, op_c, rand);
    unimplemented!("gsm auth vector via milenage 2G interworking")
}

/// A base station's view of one attach/location-update exchange. `ocr-air` drives
/// this; attackers substitute their own [`Bts`] behaviour.
#[derive(Clone, Debug, Default)]
pub struct Bts {
    pub plmn_configured: Option<Plmn>,
    pub cipher: Option<A5>,
    pub last_imsi_seen: Option<Imsi>,
}

impl Bts {
    /// Advance the exchange given an uplink message, returning the downlink
    /// response(s).
    pub fn on_uplink(&mut self, msg: &GsmMessage) -> Vec<GsmMessage> {
        let _ = msg;
        unimplemented!("bts state machine")
    }
}

/// A phone's GSM side. Camps, answers challenges, obeys the cipher command.
#[derive(Clone, Debug, Default)]
pub struct MobileStation {
    pub imsi: Option<Imsi>,
    pub tmsi: Option<Tmsi>,
}

impl MobileStation {
    pub fn on_downlink(&mut self, msg: &GsmMessage) -> Vec<GsmMessage> {
        let _ = msg;
        unimplemented!("ms state machine")
    }
}
