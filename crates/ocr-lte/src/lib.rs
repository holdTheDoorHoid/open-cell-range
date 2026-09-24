//! 4G / LTE model for Open Cell Range — the "mutual auth, but the gaps survive"
//! chapter.
//!
//! EPS-AKA lets the phone verify the network via `AUTN`, so a naive fake eNodeB
//! can no longer complete authentication. Two things still leak, and both are
//! modelled here: the **cleartext Identity Request** sent before the security
//! context exists, and the **unprotected pre-auth messages** (Attach/TAU/RRC
//! rejects) that enable bidding-down to 2G.
//!
//! ## Implementer notes (stubbed; fill the bodies)
//! - `EpsAkaVector` derives from `ocr_crypto::Milenage`; `K_ASME` per TS 33.401
//!   Annex A. Validate against a published set.
//! - Model just enough NAS/RRC to run the attacks: identity, auth, security-mode,
//!   attach/TAU accept/reject, RRC connection reject, paging.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use ocr_identity::{Guti, Imsi, Plmn};

/// EPS NAS security algorithms; the null pair (EEA0/EIA0) is legal and telling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum NasAlgorithm {
    EEA0_EIA0,
    EEA1_EIA1,
    EEA2_EIA2,
}

/// Cause values carried by reject messages; a fake cell uses these to steer the
/// UE (e.g. "EPS services not allowed" to push it off LTE).
pub type EmmCause = u8;

/// The NAS message subset the range teaches with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LteNasMessage {
    AttachRequest {
        guti: Option<Guti>,
    },
    /// Cleartext identity request — sent before security is on.
    IdentityRequest,
    IdentityResponse {
        imsi: Option<Imsi>,
    },
    AuthenticationRequest {
        rand: [u8; 16],
        autn: [u8; 16],
    },
    AuthenticationResponse {
        res: Vec<u8>,
    },
    /// Resync path: the UE tells the network its SQN is out of range.
    AuthenticationFailureSyncFailure {
        auts: Vec<u8>,
    },
    /// The other failure: the MAC did not check. The distinguishability of these
    /// two is a linkability side-channel.
    AuthenticationFailureMacFailure,
    SecurityModeCommand {
        algorithm: NasAlgorithm,
    },
    SecurityModeComplete,
    AttachAccept {
        guti: Option<Guti>,
    },
    /// Unprotected pre-auth reject — the bidding-down lever.
    AttachReject {
        cause: EmmCause,
    },
    TrackingAreaUpdateReject {
        cause: EmmCause,
    },
    /// Paging by S-TMSI or IMSI; IMSI paging is itself a signal.
    Paging {
        by_imsi: bool,
    },
}

/// RRC-layer messages that matter for the pre-auth attacks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LteRrcMessage {
    /// Broadcast identity + selection info of an LTE cell.
    SystemInformation {
        plmn: Plmn,
        tac: u16,
        cell_id: u32,
    },
    ConnectionRequest,
    ConnectionSetup,
    /// Unprotected reject; steers the UE away.
    ConnectionReject {
        wait_time: u8,
    },
    /// Measurement config/report — leaks the UE's neighbour view.
    MeasurementReport,
}

/// An EPS-AKA vector as the network computes it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EpsAkaVector {
    pub rand: [u8; 16],
    pub autn: [u8; 16],
    pub xres: Vec<u8>,
    pub k_asme: [u8; 32],
}

/// Produce an EPS-AKA vector for a challenge.
pub fn eps_aka_vector(
    k: &[u8; 16],
    op_c: &[u8; 16],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
    serving_plmn: &Plmn,
) -> EpsAkaVector {
    let _ = (k, op_c, rand, sqn, amf, serving_plmn);
    unimplemented!("eps-aka vector via milenage + K_ASME")
}

/// Whether an established NAS security context is actually protecting traffic.
/// `false` under the null algorithms.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SecurityContext {
    pub algorithm: Option<NasAlgorithm>,
    pub established: bool,
}

impl SecurityContext {
    pub fn is_protected(&self) -> bool {
        self.established && !matches!(self.algorithm, Some(NasAlgorithm::EEA0_EIA0) | None)
    }
}
