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

/// Push `value` as exactly `width` decimal digits (zero-padded) onto `out`.
/// MCC is always 3 digits and MNC is `mnc_len` digits; leading zeros are
/// significant in both, so they must be preserved.
fn push_fixed_digits(out: &mut String, value: u16, width: usize) {
    let mut digits = [0u8; 5];
    let mut v = value;
    for slot in digits.iter_mut() {
        *slot = (v % 10) as u8;
        v /= 10;
    }
    for i in (0..width).rev() {
        out.push((b'0' + digits[i]) as char);
    }
}

/// Parse a run of ASCII decimal digits into one-digit-per-byte form.
fn digits_of(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(s.bytes().map(|b| b - b'0').collect())
}

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
    ///
    /// A bare digit string does not carry the MNC length, so this assumes a
    /// **2-digit MNC**, the most common global case. Use
    /// [`Imsi::parse_with_mnc_len`] when the network's MNC is 3 digits (e.g. most
    /// North-American PLMNs). `to_digits` on the result round-trips exactly.
    pub fn parse(s: &str) -> Option<Self> {
        Self::parse_with_mnc_len(s, 2)
    }

    /// Parse with an explicit MNC length (2 or 3).
    pub fn parse_with_mnc_len(s: &str, mnc_len: u8) -> Option<Self> {
        if mnc_len != 2 && mnc_len != 3 {
            return None;
        }
        let digits = digits_of(s)?;
        let head = 3 + mnc_len as usize;
        // MCC + MNC must be present; total IMSI length is capped at 15 digits.
        if digits.len() < head || digits.len() > 15 {
            return None;
        }
        let mcc = digits[0..3].iter().fold(0u16, |a, &d| a * 10 + d as u16);
        let mnc = digits[3..head].iter().fold(0u16, |a, &d| a * 10 + d as u16);
        let msin = digits[head..].to_vec();
        Some(Imsi {
            plmn: Plmn::new(mcc, mnc, mnc_len),
            msin,
        })
    }

    /// Format back to a decimal digit string.
    pub fn to_digits(&self) -> String {
        let mut s = String::new();
        push_fixed_digits(&mut s, self.plmn.mcc, 3);
        push_fixed_digits(&mut s, self.plmn.mnc, self.plmn.mnc_len as usize);
        for &d in &self.msin {
            s.push((b'0' + d) as char);
        }
        s
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
    /// Parse an IMSI-based SUPI. Accepts the 3GPP `imsi-<digits>` form or a bare
    /// digit string; assumes a 2-digit MNC (see [`Imsi::parse`]).
    pub fn parse(s: &str) -> Option<Self> {
        Self::parse_with_mnc_len(s, 2)
    }

    /// Parse an IMSI-based SUPI with an explicit MNC length (2 or 3).
    pub fn parse_with_mnc_len(s: &str, mnc_len: u8) -> Option<Self> {
        let digits = s.strip_prefix("imsi-").unwrap_or(s);
        let imsi = Imsi::parse_with_mnc_len(digits, mnc_len)?;
        Some(Supi {
            plmn: imsi.plmn,
            msin: imsi.msin,
        })
    }

    /// Format as a bare decimal digit string (no `imsi-` prefix).
    pub fn to_digits(&self) -> String {
        Imsi {
            plmn: self.plmn,
            msin: self.msin.clone(),
        }
        .to_digits()
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
    ///
    /// The PLMN and routing indicator travel in clear (the network needs them to
    /// route to the right home network); only the MSIN is concealed.
    pub fn conceal(
        supi: &Supi,
        home: &HomeNetworkKeyPair,
        scheme: ProtectionScheme,
        routing_indicator: u16,
        rng: &mut SeededRng,
    ) -> Self {
        let concealed = ocr_crypto::suci::conceal(scheme, &home.public_key, &supi.msin, rng);
        Suci {
            plmn: supi.plmn,
            routing_indicator,
            scheme,
            concealed,
        }
    }

    /// Recover the SUPI as the home network would. `None` if concealment does not
    /// verify.
    pub fn deconceal(&self, home: &HomeNetworkKeyPair) -> Option<Supi> {
        let msin = ocr_crypto::suci::deconceal(&home.private_key, &self.concealed)?;
        Some(Supi {
            plmn: self.plmn,
            msin,
        })
    }

    /// Whether this SUCI actually protects the identity. `false` for the null
    /// scheme — the property `ocr-detect` flags.
    pub fn is_protected(&self) -> bool {
        !matches!(self.scheme, ProtectionScheme::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imsi_parse_round_trip_2digit_mnc() {
        // MCC 262 (DE), MNC 01, MSIN 0123456789.
        let imsi = Imsi::parse("262010123456789").unwrap();
        assert_eq!(imsi.plmn.mcc, 262);
        assert_eq!(imsi.plmn.mnc, 1);
        assert_eq!(imsi.plmn.mnc_len, 2);
        assert_eq!(imsi.msin, alloc::vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(imsi.to_digits(), "262010123456789");
    }

    #[test]
    fn imsi_parse_round_trip_3digit_mnc() {
        // MCC 310, MNC 260 (US), MSIN 123456789.
        let imsi = Imsi::parse_with_mnc_len("310260123456789", 3).unwrap();
        assert_eq!(imsi.plmn.mcc, 310);
        assert_eq!(imsi.plmn.mnc, 260);
        assert_eq!(imsi.plmn.mnc_len, 3);
        assert_eq!(imsi.msin, alloc::vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(imsi.to_digits(), "310260123456789");
    }

    #[test]
    fn imsi_preserves_leading_zeros() {
        // The C.4 example identity: MCC 001, MNC 01, MSIN 001002086.
        let imsi = Imsi::parse("001010012").unwrap();
        assert_eq!(imsi.plmn.mcc, 1);
        assert_eq!(imsi.plmn.mnc, 1);
        assert_eq!(imsi.to_digits(), "001010012");
    }

    #[test]
    fn imsi_rejects_bad_input() {
        assert!(Imsi::parse("").is_none());
        assert!(Imsi::parse("12abc45").is_none());
        assert!(Imsi::parse("1234").is_none()); // too short for MCC+MNC
        assert!(Imsi::parse("1234567890123456").is_none()); // > 15 digits
        assert!(Imsi::parse_with_mnc_len("310260123", 4).is_none()); // bad mnc_len
    }

    #[test]
    fn supi_parse_accepts_prefix() {
        let a = Supi::parse("imsi-262010123456789").unwrap();
        let b = Supi::parse("262010123456789").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.plmn.mcc, 262);
        assert_eq!(a.to_digits(), "262010123456789");
    }

    #[test]
    fn suci_null_scheme_round_trip_and_unprotected() {
        let mut rng = SeededRng::new(1);
        let home = HomeNetworkKeyPair::generate(&mut rng);
        let supi = Supi::parse("262010123456789").unwrap();
        let suci = Suci::conceal(&supi, &home, ProtectionScheme::Null, 0, &mut rng);
        assert!(!suci.is_protected());
        // Null scheme leaks the MSIN verbatim.
        assert_eq!(suci.concealed.ciphertext, supi.msin);
        let back = suci.deconceal(&home).unwrap();
        assert_eq!(back, supi);
    }

    #[test]
    fn suci_profile_a_round_trip_and_protected() {
        let mut rng = SeededRng::new(0xABCDEF);
        let home = HomeNetworkKeyPair::generate(&mut rng);
        let supi = Supi::parse_with_mnc_len("310260123456789", 3).unwrap();
        let suci = Suci::conceal(&supi, &home, ProtectionScheme::ProfileA, 42, &mut rng);
        assert!(suci.is_protected());
        assert_eq!(suci.routing_indicator, 42);
        assert_eq!(suci.plmn, supi.plmn);
        // MSIN is actually concealed.
        assert_ne!(suci.concealed.ciphertext, supi.msin);
        let back = suci.deconceal(&home).unwrap();
        assert_eq!(back, supi);
    }

    #[test]
    fn suci_profile_a_wrong_home_key_fails() {
        let mut rng = SeededRng::new(2);
        let home = HomeNetworkKeyPair::generate(&mut rng);
        let other = HomeNetworkKeyPair::generate(&mut rng);
        let supi = Supi::parse("262010123456789").unwrap();
        let suci = Suci::conceal(&supi, &home, ProtectionScheme::ProfileA, 0, &mut rng);
        assert!(suci.deconceal(&other).is_none());
    }
}
