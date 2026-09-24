//! 5G / NR model for Open Cell Range — the "SUCI is the fix, and here is what it
//! doesn't fix" chapter.
//!
//! In 5G the permanent identity goes on the air only as a [`Suci`], concealed
//! with the home network's public key, so the cleartext-identity request that
//! powered every prior attack is dead. This crate models that — and the seams
//! that survive it: the **null protection scheme** (spec-legal cleartext SUPI),
//! **downgrade** permissions, and the **failure-message / reallocation
//! linkability** side-channels.
//!
//! ## Implementer notes (stubbed; fill the bodies)
//! - `FiveGAkaVector` is EPS-AKA's sibling with `K_AUSF`/`K_SEAF` (TS 33.501);
//!   reuse `ocr_crypto::Milenage`.
//! - SUCI attach uses `ocr_identity::Suci`; the home network deconceals to get
//!   the SUPI. Show both the protected and null paths.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use ocr_identity::{FiveGGuti, Plmn, Suci, Supi};

/// 5G NAS security algorithms; the null pair is, again, legal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum NrAlgorithm {
    NEA0_NIA0,
    NEA1_NIA1,
    NEA2_NIA2,
}

/// Why an authentication failed, from the UE. The fact that these are
/// distinguishable on the air is the linkability weakness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthFailureCause {
    MacFailure,
    SynchFailure,
}

/// The 5G NAS message subset the range teaches with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NrNasMessage {
    /// Registration carrying a concealed identity — or a 5G-GUTI when the UE has
    /// one.
    RegistrationRequest {
        suci: Option<Suci>,
        guti: Option<FiveGGuti>,
    },
    /// In 5G the network asks for a SUCI, not a cleartext SUPI.
    IdentityRequestSuci,
    IdentityResponseSuci {
        suci: Suci,
    },
    AuthenticationRequest {
        rand: [u8; 16],
        autn: [u8; 16],
    },
    AuthenticationResponse {
        res_star: Vec<u8>,
    },
    AuthenticationFailure {
        cause: AuthFailureCause,
        auts: Option<Vec<u8>>,
    },
    SecurityModeCommand {
        algorithm: NrAlgorithm,
    },
    SecurityModeComplete,
    RegistrationAccept {
        guti: Option<FiveGGuti>,
    },
    /// Unprotected pre-auth reject — the downgrade lever survives into 5G.
    RegistrationReject {
        cause: u8,
    },
}

/// RRC-layer messages of interest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NrRrcMessage {
    SystemInformation {
        plmn: Plmn,
        tac: u32,
        cell_id: u64,
        /// Whether this cell advertises that it permits fallback to E-UTRA/2G.
        allows_downgrade: bool,
    },
    SetupRequest,
    Setup,
    Reject {
        wait_time: u8,
    },
}

/// A 5G-AKA vector.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FiveGAkaVector {
    pub rand: [u8; 16],
    pub autn: [u8; 16],
    pub xres_star: Vec<u8>,
    pub k_seaf: [u8; 32],
}

/// Produce a 5G-AKA vector.
pub fn five_g_aka_vector(
    k: &[u8; 16],
    op_c: &[u8; 16],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
    serving_plmn: &Plmn,
) -> FiveGAkaVector {
    let _ = (k, op_c, rand, sqn, amf, serving_plmn);
    unimplemented!("5g-aka vector via milenage + K_AUSF/K_SEAF")
}

/// The home network side: deconceal a SUCI to a SUPI.
pub fn deconceal_registration(
    suci: &Suci,
    home: &ocr_crypto::suci::HomeNetworkKeyPair,
) -> Option<Supi> {
    let _ = (suci, home);
    unimplemented!("home network SUCI deconceal")
}
