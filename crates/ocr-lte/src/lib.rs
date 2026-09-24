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
use hmac::{Hmac, Mac};
use ocr_crypto::Milenage;
use ocr_identity::{Guti, Imsi, Plmn};
use sha2::Sha256;

/// The TS 33.220 generic KDF is keyed HMAC over SHA-256.
type HmacSha256 = Hmac<Sha256>;

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

/// Produce an EPS-AKA vector for a challenge, as the HSS/AuC computes it
/// (3GPP TS 33.401 Annex A.2).
///
/// The MILENAGE run gives MAC-A (f1), RES (f2), CK (f3), IK (f4) and AK (f5).
/// From those:
/// - `AUTN` = (SQN XOR AK) || AMF || MAC-A — 16 octets. Because AUTN carries a
///   MAC over the network's key, a fake eNodeB that does not know K cannot forge
///   one, which is exactly what closes the naive 2G-style IMSI grab.
/// - `XRES` = RES — 8 octets.
/// - `K_ASME` = KDF(CK || IK, S) with the K_ASME input string S built by
///   [`k_asme_input`], per Annex A.2.
pub fn eps_aka_vector(
    k: &[u8; 16],
    op_c: &[u8; 16],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
    serving_plmn: &Plmn,
) -> EpsAkaVector {
    let out = Milenage::new(*k, *op_c).compute(rand, sqn, amf);

    // SQN XOR AK is both the leading field of AUTN and P1 of the K_ASME KDF, so
    // the UE, which reads it straight out of AUTN, derives the identical K_ASME.
    let mut sqn_xor_ak = [0u8; 6];
    for i in 0..6 {
        sqn_xor_ak[i] = sqn[i] ^ out.ak[i];
    }

    let mut autn = [0u8; 16];
    autn[0..6].copy_from_slice(&sqn_xor_ak);
    autn[6..8].copy_from_slice(amf);
    autn[8..16].copy_from_slice(&out.mac_a);

    let k_asme = derive_k_asme(&out.ck, &out.ik, serving_plmn, &sqn_xor_ak);

    EpsAkaVector {
        rand: *rand,
        autn,
        xres: out.res.to_vec(),
        k_asme,
    }
}

/// TS 33.220 generic key derivation function: `derived key = HMAC-SHA-256(key, S)`.
///
/// `S` is the fully assembled input string `FC || P0 || L0 || P1 || L1 || ...`;
/// the caller builds it (see [`k_asme_input`]). Returns all 32 output octets;
/// K_ASME uses the whole thing.
fn kdf(key: &[u8], s: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(s);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Assemble the K_ASME KDF input string S (TS 33.401 Annex A.2):
/// `FC(0x10) || SNid(3) || L0(0x00 0x03) || (SQN XOR AK)(6) || L1(0x00 0x06)`.
fn k_asme_input(sn_id: &[u8; 3], sqn_xor_ak: &[u8; 6]) -> [u8; 14] {
    let mut s = [0u8; 14];
    s[0] = 0x10; // FC for K_ASME
    s[1..4].copy_from_slice(sn_id); // P0 = serving network id
    s[4..6].copy_from_slice(&[0x00, 0x03]); // L0 = length of P0
    s[6..12].copy_from_slice(sqn_xor_ak); // P1 = SQN XOR AK
    s[12..14].copy_from_slice(&[0x00, 0x06]); // L1 = length of P1
    s
}

/// Derive K_ASME from CK, IK, the serving PLMN and (SQN XOR AK).
fn derive_k_asme(
    ck: &[u8; 16],
    ik: &[u8; 16],
    serving_plmn: &Plmn,
    sqn_xor_ak: &[u8; 6],
) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0..16].copy_from_slice(ck);
    key[16..32].copy_from_slice(ik);
    let s = k_asme_input(&plmn_bcd(serving_plmn), sqn_xor_ak);
    kdf(&key, &s)
}

/// Encode a serving PLMN as the 3-octet SN id (TS 24.301 / TS 24.008 BCD layout):
/// ```text
///   octet 1:  MCC2 (high nibble) | MCC1 (low nibble)
///   octet 2:  MNC3 (high nibble) | MCC3 (low nibble)   MNC3 = 0xF for a 2-digit MNC
///   octet 3:  MNC2 (high nibble) | MNC1 (low nibble)
/// ```
/// e.g. MCC 310 / MNC 260 -> `13 00 62`, MCC 244 / MNC 91 -> `42 f4 19`.
fn plmn_bcd(plmn: &Plmn) -> [u8; 3] {
    let mcc1 = (plmn.mcc / 100 % 10) as u8;
    let mcc2 = (plmn.mcc / 10 % 10) as u8;
    let mcc3 = (plmn.mcc % 10) as u8;
    let (mnc1, mnc2, mnc3) = if plmn.mnc_len == 3 {
        (
            (plmn.mnc / 100 % 10) as u8,
            (plmn.mnc / 10 % 10) as u8,
            (plmn.mnc % 10) as u8,
        )
    } else {
        ((plmn.mnc / 10 % 10) as u8, (plmn.mnc % 10) as u8, 0x0F)
    };
    [(mcc2 << 4) | mcc1, (mnc3 << 4) | mcc3, (mnc2 << 4) | mnc1]
}

/// Pack the low 48 bits of a sequence number into the 6-octet SQN field
/// (big-endian), the width MILENAGE's f1/f1* inputs expect.
fn sqn_to_bytes(sqn: u64) -> [u8; 6] {
    let b = sqn.to_be_bytes();
    let mut out = [0u8; 6];
    out.copy_from_slice(&b[2..8]);
    out
}

/// Read a 6-octet big-endian SQN field back into a `u64`.
fn sqn_from_bytes(b: &[u8; 6]) -> u64 {
    let mut wide = [0u8; 8];
    wide[2..8].copy_from_slice(b);
    u64::from_be_bytes(wide)
}

// ---- UE side: this is where mutual auth is actually enforced ----------------

/// The UE's sequence-number freshness state, modelling the SQN window of
/// TS 33.102 Annex C.2. `sqn_ms` is the highest SQN the UE has accepted; a
/// challenge whose SQN is not newer, or is implausibly far ahead, takes the
/// re-synchronisation (AUTS) path instead of being accepted. Distinguishing that
/// path from a MAC failure is the linkability side-channel the arc returns to in
/// 5G — so the two outcomes are modelled as genuinely different results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UeSqnState {
    /// Highest sequence number accepted so far.
    pub sqn_ms: u64,
    /// How far ahead of `sqn_ms` a challenge SQN may be and still be accepted.
    pub window: u64,
}

impl UeSqnState {
    /// TS 33.102 Annex C.2 uses a limit of 2^28 on how far the SEQ part may jump
    /// ahead; we model the window at that value.
    pub const DEFAULT_WINDOW: u64 = 1 << 28;

    /// A UE whose last-accepted sequence number is `sqn_ms`, with the default
    /// acceptance window.
    pub fn new(sqn_ms: u64) -> Self {
        Self {
            sqn_ms,
            window: Self::DEFAULT_WINDOW,
        }
    }

    /// Whether a recovered SQN is fresh enough to accept: strictly newer than the
    /// stored value and no more than `window` ahead of it.
    fn accepts(&self, sqn: u64) -> bool {
        sqn > self.sqn_ms && sqn - self.sqn_ms <= self.window
    }
}

/// The result of a UE checking an `AuthenticationRequest`. Each arm maps onto one
/// of the NAS messages the UE would send back (see [`UeAuthOutcome::to_nas`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UeAuthOutcome {
    /// AUTN checked out and SQN was fresh: mutual auth succeeded. `res` goes back
    /// in an `AuthenticationResponse`; `k_asme` matches the network's, so both
    /// sides now hold the same key.
    Success { res: Vec<u8>, k_asme: [u8; 32] },
    /// The MAC in AUTN did not verify — a network that does not know K (a naive
    /// fake eNodeB) cannot get past this.
    MacFailure,
    /// The MAC was fine but the SQN was out of range; `auts` lets the network
    /// re-synchronise.
    SyncFailure { auts: Vec<u8> },
}

impl UeAuthOutcome {
    /// The NAS message the UE emits for this outcome.
    pub fn to_nas(&self) -> LteNasMessage {
        match self {
            UeAuthOutcome::Success { res, .. } => {
                LteNasMessage::AuthenticationResponse { res: res.clone() }
            }
            UeAuthOutcome::MacFailure => LteNasMessage::AuthenticationFailureMacFailure,
            UeAuthOutcome::SyncFailure { auts } => {
                LteNasMessage::AuthenticationFailureSyncFailure { auts: auts.clone() }
            }
        }
    }
}

/// UE-side verification of an EPS-AKA challenge (TS 33.102 §6.3.3, reused by
/// EPS-AKA). This is the seam that makes mutual authentication real: the UE
/// recomputes the AUTN MAC under its own key and rejects anything it cannot
/// verify.
///
/// Steps: recover AK (f5) and hence SQN from AUTN, recompute XMAC (f1) over the
/// recovered SQN and the received AMF, and compare it to the MAC in AUTN. A
/// mismatch is a **MAC failure**. Only if the MAC is good is the SQN checked for
/// freshness; a stale or wildly advanced SQN yields a **sync failure** carrying
/// AUTS = (SQN_MS XOR AK*) || MAC-S (MAC-S computed with the dummy all-zero AMF
/// of TS 33.102). On success the UE advances `state.sqn_ms` and derives the same
/// K_ASME the network did.
pub fn ue_verify_challenge(
    k: &[u8; 16],
    op_c: &[u8; 16],
    state: &mut UeSqnState,
    rand: &[u8; 16],
    autn: &[u8; 16],
    serving_plmn: &Plmn,
) -> UeAuthOutcome {
    let milenage = Milenage::new(*k, *op_c);

    let mut sqn_xor_ak = [0u8; 6];
    sqn_xor_ak.copy_from_slice(&autn[0..6]);
    let mut amf = [0u8; 2];
    amf.copy_from_slice(&autn[6..8]);
    let received_mac = &autn[8..16];

    // f5 (AK) does not depend on SQN/AMF, so a throwaway compute recovers AK, and
    // from it the SQN the network used.
    let ak = milenage.compute(rand, &[0u8; 6], &[0u8; 2]).ak;
    let mut sqn_bytes = [0u8; 6];
    for i in 0..6 {
        sqn_bytes[i] = sqn_xor_ak[i] ^ ak[i];
    }

    // XMAC over the recovered SQN and the received AMF.
    let out = milenage.compute(rand, &sqn_bytes, &amf);
    if out.mac_a.as_slice() != received_mac {
        return UeAuthOutcome::MacFailure;
    }

    let sqn = sqn_from_bytes(&sqn_bytes);
    if !state.accepts(sqn) {
        // Re-synchronisation: AUTS = (SQN_MS XOR AK*) || MAC-S, MAC-S over SQN_MS
        // with the dummy all-zero AMF.
        let ak_star = milenage.f5_star(rand);
        let sqn_ms_bytes = sqn_to_bytes(state.sqn_ms);
        let mac_s = milenage.f1_star(rand, &sqn_ms_bytes, &[0u8; 2]);
        let mut auts = Vec::with_capacity(14);
        for i in 0..6 {
            auts.push(sqn_ms_bytes[i] ^ ak_star[i]);
        }
        auts.extend_from_slice(&mac_s);
        return UeAuthOutcome::SyncFailure { auts };
    }

    state.sqn_ms = sqn;
    let k_asme = derive_k_asme(&out.ck, &out.ik, serving_plmn, &sqn_xor_ak);
    UeAuthOutcome::Success {
        res: out.res.to_vec(),
        k_asme,
    }
}

/// The pre-security IMSI leak, modelled end to end.
///
/// On attach with no usable GUTI the network sends a **cleartext**
/// `IdentityRequest`, and the UE — which has no security context yet — answers
/// with its permanent `IMSI`. Both messages travel before any
/// `SecurityModeCommand`, so a fake eNodeB that can never complete AKA (see
/// [`ue_verify_challenge`]) still harvests the IMSI. Returns the (request,
/// response) pair so a test or the air layer can assert the IMSI was on the air
/// in the clear.
pub fn pre_security_identity_exchange(imsi: Imsi) -> (LteNasMessage, LteNasMessage) {
    (
        LteNasMessage::IdentityRequest,
        LteNasMessage::IdentityResponse { imsi: Some(imsi) },
    )
}

/// Whether an IMSI carried in a pre-auth `IdentityResponse` was exposed on the
/// air: true whenever the NAS security context is not actually protecting
/// traffic. This is what `ocr-detect` flags as a cleartext IMSI request.
pub fn imsi_exposed(ctx: &SecurityContext) -> bool {
    !ctx.is_protected()
}

/// Whether an established NAS security context is actually protecting traffic.
/// `false` under the null algorithms.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SecurityContext {
    pub algorithm: Option<NasAlgorithm>,
    pub established: bool,
}

impl SecurityContext {
    /// The context a completed SecurityModeCommand / SecurityModeComplete leaves
    /// behind for `algorithm`. Note that establishing the *null* pair still marks
    /// the context `established` yet leaves it unprotected — the teaching point
    /// [`SecurityContext::is_protected`] captures.
    pub fn establish(algorithm: NasAlgorithm) -> Self {
        Self {
            algorithm: Some(algorithm),
            established: true,
        }
    }

    pub fn is_protected(&self) -> bool {
        self.established && !matches!(self.algorithm, Some(NasAlgorithm::EEA0_EIA0) | None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

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
    fn arr2(s: &str) -> [u8; 2] {
        hex(s).try_into().unwrap()
    }

    // 3GPP TS 35.208 MILENAGE test set 1 — the same inputs ocr-crypto validates
    // f1..f5 against, so CK/IK/RES/AK feeding K_ASME here are known-correct.
    const K: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
    const OPC: &str = "cd63cb71954a9f4e48a5994e37a02baf";
    const RAND: &str = "23553cbe9637a89d218ae64dae47bf35";
    const SQN: &str = "ff9bb4d0b607";
    const AMF: &str = "b9b9";
    const MAC_A: &str = "4a9ffac354dfafb3";
    const RES: &str = "a54211d5e3ba50bf";
    const CK: &str = "b40ba9a3c58b2a05bbf0d987b21bf8cb";
    const IK: &str = "f769bcd751044604127672711c6d3441";
    const AK: &str = "aa689c648370";

    fn serving_plmn() -> Plmn {
        // T-Mobile US 310/260, a 3-digit MNC; SN id encodes to 13 00 62.
        Plmn::new(310, 260, 3)
    }

    #[test]
    fn plmn_bcd_matches_published_encodings() {
        // Independent anchor for the one K_ASME input not covered by the MILENAGE
        // vectors: the SN id BCD packing (TS 24.301). These two PLMN encodings are
        // widely published.
        assert_eq!(plmn_bcd(&Plmn::new(310, 260, 3)), [0x13, 0x00, 0x62]);
        assert_eq!(plmn_bcd(&Plmn::new(244, 91, 2)), [0x42, 0xf4, 0x19]);
        // 2-digit MNC leaves the MNC3 nibble as the 0xF filler.
        assert_eq!(plmn_bcd(&Plmn::new(1, 1, 2)), [0x00, 0xf1, 0x10]);
    }

    #[test]
    fn k_asme_input_string_layout() {
        // S = FC(0x10) || SNid(3) || L0(00 03) || (SQN^AK)(6) || L1(00 06).
        let sn = [0x13u8, 0x00, 0x62];
        let p1 = arr6("0102030405f6");
        let s = k_asme_input(&sn, &p1);
        assert_eq!(s[0], 0x10);
        assert_eq!(&s[1..4], &sn);
        assert_eq!(&s[4..6], &[0x00, 0x03]);
        assert_eq!(&s[6..12], &p1);
        assert_eq!(&s[12..14], &[0x00, 0x06]);
    }

    #[test]
    fn k_asme_is_full_hmac_sha256_over_annex_a2_string() {
        // Contract guard for the KDF: derive_k_asme must be exactly the 32-octet
        // HMAC-SHA-256(CK||IK, S). Recomputed here independently of the helper.
        let ck = arr16(CK);
        let ik = arr16(IK);
        let sqn = arr6(SQN);
        let ak = arr6(AK);
        let mut sqn_xor_ak = [0u8; 6];
        for i in 0..6 {
            sqn_xor_ak[i] = sqn[i] ^ ak[i];
        }
        let plmn = serving_plmn();

        let mut key = Vec::new();
        key.extend_from_slice(&ck);
        key.extend_from_slice(&ik);
        let mut s = Vec::new();
        s.push(0x10u8);
        s.extend_from_slice(&[0x13, 0x00, 0x62]); // SN id for 310/260
        s.extend_from_slice(&[0x00, 0x03]);
        s.extend_from_slice(&sqn_xor_ak);
        s.extend_from_slice(&[0x00, 0x06]);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).unwrap();
        mac.update(&s);
        let tag = mac.finalize().into_bytes();
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&tag);

        assert_eq!(derive_k_asme(&ck, &ik, &plmn, &sqn_xor_ak), expected);
    }

    #[test]
    fn eps_aka_vector_autn_and_xres_structure() {
        let v = eps_aka_vector(
            &arr16(K),
            &arr16(OPC),
            &arr16(RAND),
            &arr6(SQN),
            &arr2(AMF),
            &serving_plmn(),
        );
        // AUTN = (SQN^AK) || AMF || MAC-A.
        let sqn = arr6(SQN);
        let ak = arr6(AK);
        let mut sqn_xor_ak = [0u8; 6];
        for i in 0..6 {
            sqn_xor_ak[i] = sqn[i] ^ ak[i];
        }
        assert_eq!(&v.autn[0..6], &sqn_xor_ak);
        assert_eq!(&v.autn[6..8], &arr2(AMF));
        assert_eq!(&v.autn[8..16], &hex(MAC_A)[..]);
        // XRES == RES (f2).
        assert_eq!(v.xres, hex(RES));
        assert_eq!(v.rand, arr16(RAND));
    }

    #[test]
    fn mutual_auth_success_gives_shared_k_asme() {
        let plmn = serving_plmn();
        let v = eps_aka_vector(
            &arr16(K),
            &arr16(OPC),
            &arr16(RAND),
            &arr6(SQN),
            &arr2(AMF),
            &plmn,
        );

        // UE holds the same key and a slightly older SQN, so the challenge is fresh.
        let mut state = UeSqnState::new(sqn_from_bytes(&arr6(SQN)) - 1);
        let outcome =
            ue_verify_challenge(&arr16(K), &arr16(OPC), &mut state, &v.rand, &v.autn, &plmn);

        match outcome {
            UeAuthOutcome::Success { res, k_asme } => {
                // The UE's RES equals the network's XRES (auth check the network runs).
                assert_eq!(res, v.xres);
                // Both sides derived the identical K_ASME — the mutual key.
                assert_eq!(k_asme, v.k_asme);
            }
            other => panic!("expected success, got {other:?}"),
        }
        // The UE advanced its stored sequence number.
        assert_eq!(state.sqn_ms, sqn_from_bytes(&arr6(SQN)));
    }

    #[test]
    fn wrong_key_autn_is_mac_failure() {
        let plmn = serving_plmn();
        let v = eps_aka_vector(
            &arr16(K),
            &arr16(OPC),
            &arr16(RAND),
            &arr6(SQN),
            &arr2(AMF),
            &plmn,
        );

        // A fake eNodeB does not know K, so the UE (with the real key) rejects the
        // AUTN it produced. Model that as the UE verifying against a different key.
        let wrong_k = arr16("00000000000000000000000000000000");
        let mut state = UeSqnState::new(sqn_from_bytes(&arr6(SQN)) - 1);
        let outcome =
            ue_verify_challenge(&wrong_k, &arr16(OPC), &mut state, &v.rand, &v.autn, &plmn);
        assert_eq!(outcome, UeAuthOutcome::MacFailure);
        // A rejected challenge must not advance the sequence number.
        assert_eq!(state.sqn_ms, sqn_from_bytes(&arr6(SQN)) - 1);

        // Tampering the MAC bytes of a genuine AUTN is likewise a MAC failure.
        let mut tampered = v.autn;
        tampered[8] ^= 0x01;
        let mut state2 = UeSqnState::new(sqn_from_bytes(&arr6(SQN)) - 1);
        assert_eq!(
            ue_verify_challenge(
                &arr16(K),
                &arr16(OPC),
                &mut state2,
                &v.rand,
                &tampered,
                &plmn
            ),
            UeAuthOutcome::MacFailure
        );
    }

    #[test]
    fn stale_sqn_gives_recoverable_sync_failure() {
        let plmn = serving_plmn();
        let v = eps_aka_vector(
            &arr16(K),
            &arr16(OPC),
            &arr16(RAND),
            &arr6(SQN),
            &arr2(AMF),
            &plmn,
        );

        // UE is already ahead of the challenge SQN, so the MAC is fine but the SQN
        // is out of range: the resync (AUTS) path, NOT a MAC failure.
        let sqn_ms = sqn_from_bytes(&arr6(SQN)) + 10;
        let mut state = UeSqnState::new(sqn_ms);
        let outcome =
            ue_verify_challenge(&arr16(K), &arr16(OPC), &mut state, &v.rand, &v.autn, &plmn);

        let auts = match outcome {
            UeAuthOutcome::SyncFailure { auts } => auts,
            other => panic!("expected sync failure, got {other:?}"),
        };
        assert_eq!(auts.len(), 14);
        // A sync failure must not advance the stored sequence number.
        assert_eq!(state.sqn_ms, sqn_ms);

        // AUTS = (SQN_MS ^ AK*) || MAC-S. Recover SQN_MS and check MAC-S, proving
        // the network could actually re-synchronise from it.
        let milenage = Milenage::new(arr16(K), arr16(OPC));
        let ak_star = milenage.f5_star(&v.rand);
        let mut recovered = [0u8; 6];
        for i in 0..6 {
            recovered[i] = auts[i] ^ ak_star[i];
        }
        assert_eq!(sqn_from_bytes(&recovered), sqn_ms);
        let mac_s = milenage.f1_star(&v.rand, &recovered, &[0u8; 2]);
        assert_eq!(&auts[6..14], &mac_s);
    }

    #[test]
    fn outcome_maps_onto_nas_messages() {
        let ok = UeAuthOutcome::Success {
            res: vec![1, 2, 3],
            k_asme: [0u8; 32],
        };
        assert_eq!(
            ok.to_nas(),
            LteNasMessage::AuthenticationResponse { res: vec![1, 2, 3] }
        );
        assert_eq!(
            UeAuthOutcome::MacFailure.to_nas(),
            LteNasMessage::AuthenticationFailureMacFailure
        );
        assert_eq!(
            UeAuthOutcome::SyncFailure { auts: vec![9, 9] }.to_nas(),
            LteNasMessage::AuthenticationFailureSyncFailure { auts: vec![9, 9] }
        );
    }

    #[test]
    fn pre_security_imsi_leak() {
        let imsi = Imsi::parse("310260123456789").unwrap();
        let (req, resp) = pre_security_identity_exchange(imsi.clone());
        assert_eq!(req, LteNasMessage::IdentityRequest);
        assert_eq!(resp, LteNasMessage::IdentityResponse { imsi: Some(imsi) });

        // Before any SecurityModeCommand the context is not protecting: the IMSI
        // travels in the clear.
        let fresh = SecurityContext::default();
        assert!(!fresh.is_protected());
        assert!(imsi_exposed(&fresh));

        // Establishing the *null* pair still exposes it — a null cipher is the
        // teaching centrepiece, not real protection.
        let null_ctx = SecurityContext::establish(NasAlgorithm::EEA0_EIA0);
        assert!(!null_ctx.is_protected());
        assert!(imsi_exposed(&null_ctx));

        // A real algorithm finally closes it — but only after AKA, which is too
        // late for the identity already handed over above.
        let protected = SecurityContext::establish(NasAlgorithm::EEA2_EIA2);
        assert!(protected.is_protected());
        assert!(!imsi_exposed(&protected));
    }
}
