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
//! ## Implementer notes
//! - [`FiveGAkaVector`] is EPS-AKA's sibling with `K_AUSF`/`K_SEAF`
//!   (TS 33.501 Annex A); it reuses [`ocr_crypto::Milenage`] for the MAC-A / RES
//!   / CK / IK / AK layer and the TS 33.220 generic KDF (HMAC-SHA-256) for the
//!   5G key hierarchy.
//! - SUCI attach uses [`ocr_identity::Suci`]; the home network deconceals to get
//!   the SUPI. [`deconceal_registration`] is the home side; [`observer_recovers_supi`]
//!   is what a keyless on-air attacker can pull out — nothing under a real
//!   scheme, the whole SUPI under the null scheme.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use ocr_crypto::suci::HomeNetworkKeyPair;
use ocr_crypto::Milenage;
use ocr_identity::{FiveGGuti, Plmn, Suci, Supi};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

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

/// A structured authentication failure, as the UE would report it on the air.
///
/// The teaching point lives in [`AuthFailureCause`]: a `MacFailure` says only
/// "the AUTN's MAC did not match the key on *this* SIM", whereas a
/// `SynchFailure` says "the MAC matched — this AUTN really is for this
/// subscriber — but the sequence number was stale". So replaying a captured
/// `AUTN` and watching which failure comes back tells an attacker whether that
/// `AUTN` belongs to the subscriber in front of them. Concealing the SUPI does
/// not close this: the failure message itself is the oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationFailure {
    pub cause: AuthFailureCause,
    /// Present only for a `SynchFailure`: the 14-byte AUTS resynchronisation
    /// token (`Conc(SQN_MS) || MAC-S`).
    pub auts: Option<Vec<u8>>,
}

/// The UE's decision after checking an `AuthenticationRequest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UeAuthResponse {
    /// MAC-A verified and the sequence number was fresh: the UE has authenticated
    /// the network and answers with `RES*`, which the network compares to its
    /// stored `XRES*`.
    Response { res_star: Vec<u8> },
    /// Authentication did not complete. `cause` is exactly what the UE would put
    /// on the air, causes distinguishable (the linkability seam).
    Failure(AuthenticationFailure),
}

// ---- TS 33.220 generic KDF (HMAC-SHA-256) --------------------------------

/// HMAC-SHA-256 over `data`, returning the full 32-byte tag. HMAC accepts a key
/// of any length, so this never fails.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Build the KDF input string `S = FC || P0 || L0 || P1 || L1 || ...` per
/// TS 33.220 Annex B, where each `Li` is the two-octet big-endian length of the
/// preceding `Pi`. The derived key is then `HMAC-SHA-256(Key, S)`.
fn kdf_input(fc: u8, params: &[&[u8]]) -> Vec<u8> {
    let mut s = Vec::new();
    s.push(fc);
    for p in params {
        s.extend_from_slice(p);
        s.extend_from_slice(&(p.len() as u16).to_be_bytes());
    }
    s
}

/// Push `v` as exactly three decimal digits (leading zeros significant).
fn push3(out: &mut String, v: u16) {
    let v = v % 1000;
    out.push((b'0' + (v / 100) as u8) as char);
    out.push((b'0' + ((v / 10) % 10) as u8) as char);
    out.push((b'0' + (v % 10) as u8) as char);
}

/// The serving-network name used as the KDF `P0`, per TS 33.501 clause 6.1.1.4:
/// ASCII `"5G:mnc<MNC>.mcc<MCC>.3gppnetwork.org"` with the MNC always three
/// digits (a two-digit MNC is left-padded with a zero) and the MCC three digits.
fn serving_network_name(plmn: &Plmn) -> String {
    let mut s = String::new();
    s.push_str("5G:mnc");
    push3(&mut s, plmn.mnc);
    s.push_str(".mcc");
    push3(&mut s, plmn.mcc);
    s.push_str(".3gppnetwork.org");
    s
}

/// `RES*` / `XRES*` (TS 33.501 Annex A.4): `HMAC-SHA-256(CK||IK, FC(0x6B) ||
/// SNN || L || RAND || L || RES || L)`, taking the **least-significant** 128
/// bits of the tag. Network and UE run the identical function, so a matching
/// pair proves each side holds the same key — the mutual-auth check.
fn res_star(ck: &[u8; 16], ik: &[u8; 16], rand: &[u8; 16], res: &[u8; 8], snn: &str) -> Vec<u8> {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);
    let s = kdf_input(0x6B, &[snn.as_bytes(), rand, res]);
    hmac_sha256(&key, &s)[16..].to_vec()
}

/// `K_SEAF` (TS 33.501): first `K_AUSF` per Annex A.2 (FC 0x6A, key `CK||IK`,
/// `P0 = SNN`, `P1 = SQN XOR AK`), then `K_SEAF` per Annex A.6 (FC 0x6C, key
/// `K_AUSF`, `P0 = SNN`).
fn k_seaf(ck: &[u8; 16], ik: &[u8; 16], sqn_xor_ak: &[u8; 6], snn: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);
    let k_ausf = hmac_sha256(&key, &kdf_input(0x6A, &[snn.as_bytes(), sqn_xor_ak]));
    hmac_sha256(&k_ausf, &kdf_input(0x6C, &[snn.as_bytes()]))
}

/// XOR two 6-byte sequence-number-width values.
fn xor6(a: &[u8; 6], b: &[u8; 6]) -> [u8; 6] {
    let mut out = [0u8; 6];
    for (o, (x, y)) in out.iter_mut().zip(a.iter().zip(b.iter())) {
        *o = x ^ y;
    }
    out
}

/// Interpret a 6-byte big-endian sequence number as a `u64`.
fn be48(x: &[u8; 6]) -> u64 {
    x.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

/// Produce a 5G-AKA vector (network / AUSF side).
///
/// Runs MILENAGE for MAC-A/RES/CK/IK/AK, assembles `AUTN = (SQN XOR AK) || AMF
/// || MAC-A`, derives `XRES*` (Annex A.4) and `K_SEAF` (via `K_AUSF`, Annex
/// A.2 + A.6). `serving_plmn` fixes the serving-network name bound into every
/// derivation.
pub fn five_g_aka_vector(
    k: &[u8; 16],
    op_c: &[u8; 16],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
    serving_plmn: &Plmn,
) -> FiveGAkaVector {
    let milenage = Milenage::new(*k, *op_c);
    let out = milenage.compute(rand, sqn, amf);

    let sqn_xor_ak = xor6(sqn, &out.ak);
    let mut autn = [0u8; 16];
    autn[0..6].copy_from_slice(&sqn_xor_ak);
    autn[6..8].copy_from_slice(amf);
    autn[8..16].copy_from_slice(&out.mac_a);

    let snn = serving_network_name(serving_plmn);
    let xres_star = res_star(&out.ck, &out.ik, rand, &out.res, &snn);
    let k_seaf = k_seaf(&out.ck, &out.ik, &sqn_xor_ak, &snn);

    FiveGAkaVector {
        rand: *rand,
        autn,
        xres_star,
        k_seaf,
    }
}

/// The UE side of 5G-AKA: check an `AuthenticationRequest` and decide.
///
/// The UE recovers `SQN = AUTN[0..6] XOR AK`, recomputes MAC-A over the recovered
/// `SQN` and the AMF carried in the AUTN, and:
/// - if the MAC does not match → [`AuthFailureCause::MacFailure`] (no AUTS);
/// - else if the recovered `SQN` is not ahead of the UE's stored
///   `expected_sqn` → [`AuthFailureCause::SynchFailure`] with an AUTS token;
/// - else → success, returning `RES*`, which equals the network's `XRES*`.
///
/// `expected_sqn` models the UE's stored `SQN_MS`; freshness is the simple
/// monotonic rule (accept iff the received sequence number is strictly greater),
/// which is all the teaching arc needs.
pub fn ue_authenticate(
    k: &[u8; 16],
    op_c: &[u8; 16],
    rand: &[u8; 16],
    autn: &[u8; 16],
    expected_sqn: &[u8; 6],
    serving_plmn: &Plmn,
) -> UeAuthResponse {
    let milenage = Milenage::new(*k, *op_c);
    let amf: [u8; 2] = [autn[6], autn[7]];

    // AK (f5) depends only on RAND, so any SQN recovers it; use it to unmask the
    // sequence number the network sent.
    let ak = milenage.compute(rand, &[0u8; 6], &amf).ak;
    let received_sqn_xor_ak: [u8; 6] = autn[0..6].try_into().expect("6-byte slice");
    let received_sqn = xor6(&received_sqn_xor_ak, &ak);

    // Recompute the full MILENAGE outputs with the recovered SQN and check MAC-A.
    let out = milenage.compute(rand, &received_sqn, &amf);
    let received_mac: [u8; 8] = autn[8..16].try_into().expect("8-byte slice");
    if out.mac_a != received_mac {
        return UeAuthResponse::Failure(AuthenticationFailure {
            cause: AuthFailureCause::MacFailure,
            auts: None,
        });
    }

    // MAC verified: the AUTN really is for this subscriber. Now check freshness.
    if be48(&received_sqn) <= be48(expected_sqn) {
        // Resynchronisation: AUTS = (SQN_MS XOR AK*) || MAC-S, with MAC-S (f1*)
        // computed under the default all-zero AMF (TS 33.102 clause 6.3.3).
        let ak_star = milenage.f5_star(rand);
        let mac_s = milenage.f1_star(rand, expected_sqn, &[0u8; 2]);
        let mut auts = Vec::with_capacity(14);
        auts.extend_from_slice(&xor6(expected_sqn, &ak_star));
        auts.extend_from_slice(&mac_s);
        return UeAuthResponse::Failure(AuthenticationFailure {
            cause: AuthFailureCause::SynchFailure,
            auts: Some(auts),
        });
    }

    let snn = serving_network_name(serving_plmn);
    UeAuthResponse::Response {
        res_star: res_star(&out.ck, &out.ik, rand, &out.res, &snn),
    }
}

/// The home network side: deconceal a SUCI to a SUPI. Returns `None` when the
/// concealment does not verify (wrong home key, or a tampered payload).
pub fn deconceal_registration(suci: &Suci, home: &HomeNetworkKeyPair) -> Option<Supi> {
    suci.deconceal(home)
}

/// What a passive, keyless on-air observer can recover from a SUCI.
///
/// This is the entire 5G identity fix in one function, and its optional-ness:
/// under a real protection scheme the observer gets `None` (the SUPI is
/// concealed with the home network's public key, which the observer does not
/// hold), but under the spec-legal **null scheme** the "ciphertext" *is* the
/// plaintext MSIN, so the observer reconstructs the full SUPI with no key at
/// all — exactly the plaintext-identity capture 5G was meant to end.
pub fn observer_recovers_supi(suci: &Suci) -> Option<Supi> {
    if suci.is_protected() {
        None
    } else {
        Some(Supi {
            plmn: suci.plmn,
            msin: suci.concealed.ciphertext.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ocr_crypto::suci::{HomeNetworkKeyPair, ProtectionScheme};
    use ocr_crypto::SeededRng;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn arr16(s: &str) -> [u8; 16] {
        hex(s).try_into().unwrap()
    }
    fn arr6(s: &str) -> [u8; 6] {
        hex(s).try_into().unwrap()
    }

    // 3GPP TS 35.208 MILENAGE test set 1 — a published, exact vector. The 5G-AKA
    // KDF layer (XRES*, K_AUSF, K_SEAF) built on top of it is asserted by
    // internal agreement (network XRES* == UE RES*) and determinism rather than
    // an exact vector: TS 33.501 Annex A defines the KDFs but publishes no worked
    // numeric example for them, so there is nothing authoritative to pin against.
    const K: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
    const OP_C: &str = "cd63cb71954a9f4e48a5994e37a02baf";
    const RAND: &str = "23553cbe9637a89d218ae64dae47bf35";
    const SQN: &str = "ff9bb4d0b607";
    const AMF: &str = "b9b9";

    fn test_plmn() -> Plmn {
        // MCC 001, MNC 01 — the TS 33.501 Annex C example home network.
        Plmn::new(1, 1, 2)
    }

    #[test]
    fn serving_network_name_is_3gpp_form() {
        // Two-digit MNC 01 is left-padded to three digits; MCC 001 stays 001.
        assert_eq!(
            serving_network_name(&test_plmn()),
            "5G:mnc001.mcc001.3gppnetwork.org"
        );
        // A three-digit MNC (US 310/260) is used verbatim.
        assert_eq!(
            serving_network_name(&Plmn::new(310, 260, 3)),
            "5G:mnc260.mcc310.3gppnetwork.org"
        );
    }

    #[test]
    fn five_g_aka_autn_structure() {
        let v = five_g_aka_vector(
            &arr16(K),
            &arr16(OP_C),
            &arr16(RAND),
            &arr6(SQN),
            &hex(AMF).try_into().unwrap(),
            &test_plmn(),
        );
        // AUTN = (SQN XOR AK) || AMF || MAC-A. The AMF sits in bytes 6..8.
        assert_eq!(&v.autn[6..8], &hex(AMF)[..]);
        assert_eq!(v.xres_star.len(), 16);
        assert_eq!(v.k_seaf.len(), 32);
        assert_eq!(v.rand, arr16(RAND));
    }

    #[test]
    fn network_xres_star_equals_ue_res_star() {
        // The core mutual-auth agreement: the network's XRES* and the UE's RES*
        // are byte-identical when both hold the same key.
        let plmn = test_plmn();
        let v = five_g_aka_vector(
            &arr16(K),
            &arr16(OP_C),
            &arr16(RAND),
            &arr6(SQN),
            &hex(AMF).try_into().unwrap(),
            &plmn,
        );
        // UE stored SQN is one behind, so the network's SQN is fresh.
        let mut expected = arr6(SQN);
        expected[5] -= 1;
        let resp = ue_authenticate(
            &arr16(K),
            &arr16(OP_C),
            &arr16(RAND),
            &v.autn,
            &expected,
            &plmn,
        );
        match resp {
            UeAuthResponse::Response { res_star } => assert_eq!(res_star, v.xres_star),
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[test]
    fn k_seaf_is_deterministic() {
        let inputs = || {
            five_g_aka_vector(
                &arr16(K),
                &arr16(OP_C),
                &arr16(RAND),
                &arr6(SQN),
                &hex(AMF).try_into().unwrap(),
                &test_plmn(),
            )
        };
        assert_eq!(inputs().k_seaf, inputs().k_seaf);
        // And it is not trivially zero.
        assert_ne!(inputs().k_seaf, [0u8; 32]);
    }

    #[test]
    fn ue_reports_mac_failure_on_bad_autn() {
        let plmn = test_plmn();
        let mut v = five_g_aka_vector(
            &arr16(K),
            &arr16(OP_C),
            &arr16(RAND),
            &arr6(SQN),
            &hex(AMF).try_into().unwrap(),
            &plmn,
        );
        // Corrupt the MAC-A field of the AUTN.
        v.autn[15] ^= 0x01;
        let mut expected = arr6(SQN);
        expected[5] -= 1;
        let resp = ue_authenticate(
            &arr16(K),
            &arr16(OP_C),
            &arr16(RAND),
            &v.autn,
            &expected,
            &plmn,
        );
        assert_eq!(
            resp,
            UeAuthResponse::Failure(AuthenticationFailure {
                cause: AuthFailureCause::MacFailure,
                auts: None,
            })
        );
    }

    #[test]
    fn ue_reports_synch_failure_on_stale_sqn() {
        let plmn = test_plmn();
        // Untampered AUTN => MAC verifies. But the UE's stored SQN is ahead of
        // the one in the AUTN, so the sequence number is stale.
        let v = five_g_aka_vector(
            &arr16(K),
            &arr16(OP_C),
            &arr16(RAND),
            &arr6(SQN),
            &hex(AMF).try_into().unwrap(),
            &plmn,
        );
        let expected = arr6("ffffffffffff"); // maximal: everything is stale
        let resp = ue_authenticate(
            &arr16(K),
            &arr16(OP_C),
            &arr16(RAND),
            &v.autn,
            &expected,
            &plmn,
        );
        match resp {
            UeAuthResponse::Failure(AuthenticationFailure {
                cause: AuthFailureCause::SynchFailure,
                auts: Some(auts),
            }) => assert_eq!(auts.len(), 14), // Conc(SQN_MS)[6] || MAC-S[8]
            other => panic!("expected synch failure with AUTS, got {other:?}"),
        }
    }

    #[test]
    fn the_two_failure_causes_are_distinguishable() {
        // This is the linkability seam stated as a test: the same replayed AUTN
        // yields different, observable outcomes depending on whether it belongs
        // to the subscriber — a MAC failure (not this subscriber) versus a synch
        // failure (this subscriber, stale counter).
        assert_ne!(AuthFailureCause::MacFailure, AuthFailureCause::SynchFailure);
    }

    #[test]
    fn suci_profile_a_conceals_from_attacker_and_home_deconceals() {
        let mut rng = SeededRng::new(0x5EED_0F1E);
        let home = HomeNetworkKeyPair::generate(&mut rng);
        // The attacker holds its own key pair, never the home network's private key.
        let attacker = HomeNetworkKeyPair::generate(&mut rng);
        let supi = Supi::parse_with_mnc_len("310260123456789", 3).unwrap();

        let suci = Suci::conceal(&supi, &home, ProtectionScheme::ProfileA, 7, &mut rng);

        // The fix, working: the SUCI is protected, the MSIN is not on the air in
        // the clear, and a keyless observer gets nothing.
        assert!(suci.is_protected());
        assert_ne!(suci.concealed.ciphertext, supi.msin);
        assert!(observer_recovers_supi(&suci).is_none());
        // Even holding *a* home key that is not *the* home key recovers nothing.
        assert!(deconceal_registration(&suci, &attacker).is_none());

        // The home network, holding the matching private key, recovers the SUPI.
        assert_eq!(deconceal_registration(&suci, &home), Some(supi));
    }

    #[test]
    fn suci_null_scheme_leaks_supi_in_the_clear() {
        let mut rng = SeededRng::new(0xBADC0DE);
        let home = HomeNetworkKeyPair::generate(&mut rng);
        let supi = Supi::parse_with_mnc_len("310260123456789", 3).unwrap();

        let suci = Suci::conceal(&supi, &home, ProtectionScheme::Null, 0, &mut rng);

        // The fix, configured off: null scheme puts the MSIN on the air verbatim,
        // and a keyless observer reconstructs the whole SUPI.
        assert!(!suci.is_protected());
        assert_eq!(suci.concealed.ciphertext, supi.msin);
        assert_eq!(observer_recovers_supi(&suci), Some(supi.clone()));
        // The home network still recovers it too, of course.
        assert_eq!(deconceal_registration(&suci, &home), Some(supi));
    }
}
