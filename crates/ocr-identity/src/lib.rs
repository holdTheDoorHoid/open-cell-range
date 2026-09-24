//! Cellular subscriber identifiers and SUCI concealment for Open Cell Range.
//!
//! The identifiers here are what every attack in the range is ultimately about:
//! a permanent id that names a human ([`Imsi`] / [`Supi`]), the temporary ids
//! meant to keep it off the air ([`Tmsi`], [`Guti`], [`FiveGGuti`]), and the
//! concealed form that finally protects it in 5G ([`Suci`]).
//!
//! ## Implementer notes (stubbed; fill the bodies)
//! - Parse and format IMSI/SUPI as MCC (3 digits) + MNC (2 or 3) + MSIN.
//! - [`Suci::conceal`] wraps `ocr_crypto::suci`; validate the Profile A path
//!   against TS 33.501 Annex C.
//! - Keep everything `no_std`; identifiers are small and should be `Copy` where
//!   they can be.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use ocr_crypto::suci::{Concealed, HomeNetworkKeyPair, ProtectionScheme};
use ocr_crypto::SeededRng;

/// A PLMN: Mobile Country Code + Mobile Network Code. Names a carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plmn {
    /// 3 BCD digits.
    pub mcc: u16,
    /// 2 or 3 BCD digits; `mnc_len` records which.
    pub mnc: u16,
    pub mnc_len: u8,
}

impl Plmn {
    pub fn new(mcc: u16, mnc: u16, mnc_len: u8) -> Self {
        Self { mcc, mnc, mnc_len }
    }
}

/// International Mobile Subscriber Identity — the permanent id in 2G/3G/4G.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imsi {
    pub plmn: Plmn,
    /// Mobile Subscriber Identification Number, the per-subscriber tail.
    pub msin: Vec<u8>,
}

impl Imsi {
    /// Parse from a decimal digit string like "310150123456789".
    pub fn parse(s: &str) -> Option<Self> {
        let _ = s;
        unimplemented!("imsi parse")
    }
    /// Format back to a decimal digit string.
    pub fn to_digits(&self) -> String {
        unimplemented!("imsi to_digits")
    }
}

/// Subscription Permanent Identifier — the 5G permanent id. In the IMSI-based
/// form it carries the same PLMN + MSIN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Supi {
    pub plmn: Plmn,
    pub msin: Vec<u8>,
}

impl Supi {
    pub fn parse(s: &str) -> Option<Self> {
        let _ = s;
        unimplemented!("supi parse")
    }
}

/// Temporary Mobile Subscriber Identity (2G/3G) / P-TMSI. Meant to be short-lived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tmsi(pub u32);

/// Globally Unique Temporary Identity (4G): PLMN + MME id + M-TMSI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guti {
    pub plmn: Plmn,
    pub mme_group_id: u16,
    pub mme_code: u8,
    pub m_tmsi: u32,
}

/// 5G-GUTI. Its reallocation cadence is a teaching point: too infrequent and the
/// "temporary" id is durable enough to track.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FiveGGuti {
    pub plmn: Plmn,
    pub amf_region_id: u8,
    pub amf_set_id: u16,
    pub amf_pointer: u8,
    pub tmsi: u32,
}

/// Subscription Concealed Identifier — the SUPI protected for transmission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Suci {
    pub plmn: Plmn,
    /// The routing indicator, sent in clear so the network can route to the
    /// right home network / key.
    pub routing_indicator: u16,
    pub scheme: ProtectionScheme,
    /// The concealed MSIN payload (or the plaintext MSIN under the null scheme).
    pub concealed: Concealed,
}

impl Suci {
    /// Conceal a SUPI under a scheme using the home network's public key.
    pub fn conceal(
        supi: &Supi,
        home: &HomeNetworkKeyPair,
        scheme: ProtectionScheme,
        routing_indicator: u16,
        rng: &mut SeededRng,
    ) -> Self {
        let _ = (supi, home, scheme, routing_indicator, rng);
        unimplemented!("suci conceal")
    }

    /// Recover the SUPI as the home network would. `None` if concealment does not
    /// verify.
    pub fn deconceal(&self, home: &HomeNetworkKeyPair) -> Option<Supi> {
        let _ = home;
        unimplemented!("suci deconceal")
    }

    /// Whether this SUCI actually protects the identity. `false` for the null
    /// scheme — the property `ocr-detect` flags.
    pub fn is_protected(&self) -> bool {
        !matches!(self.scheme, ProtectionScheme::Null)
    }
}
