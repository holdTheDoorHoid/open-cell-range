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
use ocr_crypto::Milenage;
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

/// Fixed sequence number fed to MILENAGE's f1 branch when deriving a 2G triplet.
///
/// The GSM triplet `(RAND, SRES, Kc)` is built entirely from f2/f3/f4
/// (RES/CK/IK), and none of those depend on `SQN` or `AMF` — only f1/f1*
/// (MAC-A/MAC-S) do, and the triplet never uses them. A 2G AuC likewise never
/// exposes `SQN`/`AMF`. So any fixed value is equally correct here and cannot
/// leak into the triplet; all-zero is chosen purely for reproducibility.
const GSM_TRIPLET_SQN: [u8; 6] = [0u8; 6];
/// Fixed authentication management field, paired with [`GSM_TRIPLET_SQN`]. Same
/// reasoning: it feeds only f1/f1*, which the GSM triplet discards.
const GSM_TRIPLET_AMF: [u8; 2] = [0u8; 2];

/// GSM reject cause 0x03 ("Illegal MS") — the stand-in cause the model uses when
/// the network cannot complete authentication (SRES mismatch).
const CAUSE_ILLEGAL_MS: u8 = 0x03;

/// Compute the 2G triplet for a challenge, as the network's AuC does, by running
/// MILENAGE and applying the 3GPP TS 33.102 §6.8.1.2 UMTS→GSM interworking:
///
/// - `SRES` (c2) = `XRES[0..4] XOR XRES[4..8]`
/// - `Kc`   (c3) = `CK[0..8] XOR CK[8..16] XOR IK[0..8] XOR IK[8..16]`
///
/// `op_c` is the derived operator constant `OPc` (not the raw `OP`); callers
/// holding `OP` should first run [`ocr_crypto::Milenage::op_c_from_op`].
pub fn auth_vector(k: &[u8; 16], op_c: &[u8; 16], rand: &[u8; 16]) -> GsmAuthVector {
    let out = Milenage::new(*k, *op_c).compute(rand, &GSM_TRIPLET_SQN, &GSM_TRIPLET_AMF);

    // c2: SRES = first half XOR second half of the 8-byte XRES.
    let mut sres = [0u8; 4];
    for (i, s) in sres.iter_mut().enumerate() {
        *s = out.res[i] ^ out.res[i + 4];
    }

    // c3: Kc = the four 64-bit halves of CK and IK, all XORed together.
    let mut kc = [0u8; 8];
    for (i, byte) in kc.iter_mut().enumerate() {
        *byte = out.ck[i] ^ out.ck[i + 8] ^ out.ik[i] ^ out.ik[i + 8];
    }

    GsmAuthVector {
        rand: *rand,
        sres,
        kc,
    }
}

/// A base station's view of one attach/location-update exchange. `ocr-air` drives
/// this; attackers substitute their own [`Bts`] behaviour (out-signal the real
/// cell, request the IMSI, command `A5/0`).
///
/// The first three fields are the observable state a drill scores on: which cell
/// it claims to be, the cipher it negotiated, and any IMSI it caught. The rest is
/// configuration for the exchange.
#[derive(Clone, Debug)]
pub struct Bts {
    pub plmn_configured: Option<Plmn>,
    /// The cipher the network chose (set when it commands cipher mode). `None`
    /// until the exchange reaches that step.
    pub cipher: Option<A5>,
    /// The permanent identity this cell caught in cleartext, if any. This is the
    /// whole prize of a 2G IMSI catcher.
    pub last_imsi_seen: Option<Imsi>,

    // --- configuration -----------------------------------------------------
    /// Location/tracking area this cell advertises (LAC), broadcast in SI.
    pub lac: u16,
    /// Cell identity broadcast in SI; with `lac` it is what location tracking
    /// keys on.
    pub cell_id: u16,
    /// Whether the network issues `IdentityRequest(IMSI)` on attach. A real 2G
    /// network does this whenever it does not recognise the phone's TMSI — and
    /// because it happens *before* authentication, it is exactly the lever a
    /// catcher pulls.
    pub request_imsi: bool,
    /// The cipher the network will command. A rogue cell sets this to
    /// [`A5::A5_0`]; the phone has no way to refuse.
    pub commanded_cipher: A5,
    /// The triplet the network challenges with. `None` models a pure catcher
    /// that holds no keys and skips authentication entirely — it already has the
    /// IMSI, which leaked before any challenge.
    pub auth: Option<GsmAuthVector>,
    /// TMSI to hand back in `LocationUpdateAccept`, if reallocating one.
    pub assign_tmsi: Option<Tmsi>,
    /// Set once an `AuthenticationResponse` matched the configured triplet. Stays
    /// `false` for a catcher that cannot authenticate — the "authentication the
    /// network could not complete" signal a detector keys on.
    pub authenticated: bool,
}

impl Default for Bts {
    fn default() -> Self {
        Self {
            plmn_configured: None,
            cipher: None,
            last_imsi_seen: None,
            lac: 0,
            cell_id: 0,
            // A baseline 2G network still asks for the IMSI on first contact and
            // still uses a real cipher; the "broken by design" facts are the
            // request-before-auth ordering and the network's free choice of
            // cipher, not a malicious default.
            request_imsi: true,
            commanded_cipher: A5::A5_1,
            auth: None,
            assign_tmsi: None,
            authenticated: false,
        }
    }
}

impl Bts {
    /// The cell's broadcast identity as it appears on the BCCH. `ocr-air` emits
    /// this to make a UE camp; a rogue cell just pairs it with a high signal.
    pub fn broadcast(&self) -> GsmMessage {
        GsmMessage::SystemInformation {
            plmn: self.plmn_configured.unwrap_or_else(|| Plmn::new(0, 0, 2)),
            lac: self.lac,
            cell_id: self.cell_id,
        }
    }

    /// Choose the cipher and command it. Records the choice in `cipher`.
    fn command_cipher(&mut self) -> Vec<GsmMessage> {
        self.cipher = Some(self.commanded_cipher);
        alloc::vec![GsmMessage::CipherModeCommand {
            algorithm: self.commanded_cipher,
        }]
    }

    /// After identity (and optional authentication), either challenge or, if no
    /// triplet is configured, go straight to commanding the cipher.
    fn challenge_or_cipher(&mut self) -> Vec<GsmMessage> {
        match &self.auth {
            Some(av) => alloc::vec![GsmMessage::AuthenticationRequest { rand: av.rand }],
            None => self.command_cipher(),
        }
    }

    /// Advance the exchange given an uplink message, returning the downlink
    /// response(s).
    pub fn on_uplink(&mut self, msg: &GsmMessage) -> Vec<GsmMessage> {
        match msg {
            GsmMessage::LocationUpdateRequest { .. } => {
                if self.request_imsi {
                    // Ask for the permanent identity *before* any security
                    // context exists. This is the 2G original sin.
                    alloc::vec![GsmMessage::IdentityRequest {
                        id_type: IdentityType::Imsi,
                    }]
                } else {
                    self.challenge_or_cipher()
                }
            }
            GsmMessage::IdentityResponse { imsi } => {
                if let Some(imsi) = imsi {
                    // Caught in cleartext, with no authentication having run.
                    self.last_imsi_seen = Some(imsi.clone());
                }
                self.challenge_or_cipher()
            }
            GsmMessage::AuthenticationResponse { sres } => match &self.auth {
                Some(av) if av.sres == *sres => {
                    self.authenticated = true;
                    self.command_cipher()
                }
                Some(_) => {
                    // Wrong SRES: the network cannot complete authentication.
                    alloc::vec![GsmMessage::LocationUpdateReject {
                        cause: CAUSE_ILLEGAL_MS,
                    }]
                }
                None => self.command_cipher(),
            },
            GsmMessage::CipherModeComplete => {
                alloc::vec![GsmMessage::LocationUpdateAccept {
                    tmsi: self.assign_tmsi,
                }]
            }
            // Broadcasts and downlink-only messages are not uplink stimuli.
            _ => Vec::new(),
        }
    }
}

/// A phone's GSM side. Camps, answers challenges, and obeys the cipher command —
/// including [`A5::A5_0`], which it has no way to refuse.
#[derive(Clone, Debug, Default)]
pub struct MobileStation {
    pub imsi: Option<Imsi>,
    pub tmsi: Option<Tmsi>,
    /// Subscriber key `K`; needed to answer an `AuthenticationRequest`. Absent on
    /// a phone the drill only wants to leak an IMSI from.
    pub k: Option<[u8; 16]>,
    /// Derived operator constant `OPc`, paired with `k`.
    pub op_c: Option<[u8; 16]>,
    /// The cipher the phone last accepted. Records that it complied with whatever
    /// the network commanded.
    pub cipher: Option<A5>,
}

impl MobileStation {
    /// Answer a downlink message, returning the uplink response(s).
    pub fn on_downlink(&mut self, msg: &GsmMessage) -> Vec<GsmMessage> {
        match msg {
            GsmMessage::SystemInformation { .. } => {
                // Camp on the cell and start a location update.
                alloc::vec![GsmMessage::LocationUpdateRequest { tmsi: self.tmsi }]
            }
            GsmMessage::IdentityRequest { id_type } => match id_type {
                // The phone hands over the permanent identity with no
                // authentication of the network — the 2G weakness in one line.
                IdentityType::Imsi => alloc::vec![GsmMessage::IdentityResponse {
                    imsi: self.imsi.clone(),
                }],
                // TMSI/IMEI requests are not the identity the range teaches with;
                // model them as answered without an IMSI.
                IdentityType::Tmsi | IdentityType::Imei => {
                    alloc::vec![GsmMessage::IdentityResponse { imsi: None }]
                }
            },
            GsmMessage::AuthenticationRequest { rand } => {
                let sres = match (self.k, self.op_c) {
                    (Some(k), Some(op_c)) => auth_vector(&k, &op_c, rand).sres,
                    // No key provisioned: cannot compute a real SRES. Answer with
                    // zeroes so the exchange still advances (it will be rejected).
                    _ => [0u8; 4],
                };
                alloc::vec![GsmMessage::AuthenticationResponse { sres }]
            }
            GsmMessage::CipherModeCommand { algorithm } => {
                // Obey unconditionally — the phone cannot refuse a cipher, not
                // even the null one.
                self.cipher = Some(*algorithm);
                alloc::vec![GsmMessage::CipherModeComplete]
            }
            GsmMessage::LocationUpdateAccept { tmsi } => {
                if let Some(tmsi) = tmsi {
                    self.tmsi = Some(*tmsi);
                }
                Vec::new()
            }
            // Reject ends the attempt; uplink-only messages are not stimuli.
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex16(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    // MILENAGE test set 1 (3GPP TS 35.208), reused so the triplet can be checked
    // against outputs the crypto crate already validates.
    const TS1_K: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
    const TS1_OPC: &str = "cd63cb71954a9f4e48a5994e37a02baf";
    const TS1_RAND: &str = "23553cbe9637a89d218ae64dae47bf35";

    fn test_imsi() -> Imsi {
        Imsi::parse("262010123456789").unwrap()
    }

    /// Drive a full ping-pong exchange: the BTS broadcast is the seed, the MS
    /// answers each downlink, the BTS answers each uplink, until one side falls
    /// silent. Returns the whole transcript in chronological order.
    fn drive(bts: &mut Bts, ms: &mut MobileStation) -> Vec<GsmMessage> {
        let mut transcript = Vec::new();
        let mut downlink = alloc::vec![bts.broadcast()];
        for _ in 0..32 {
            if downlink.is_empty() {
                break;
            }
            let mut uplink = Vec::new();
            for m in &downlink {
                transcript.push(m.clone());
                uplink.extend(ms.on_downlink(m));
            }
            if uplink.is_empty() {
                break;
            }
            let mut next = Vec::new();
            for m in &uplink {
                transcript.push(m.clone());
                next.extend(bts.on_uplink(m));
            }
            downlink = next;
        }
        transcript
    }

    fn count(transcript: &[GsmMessage], pred: impl Fn(&GsmMessage) -> bool) -> usize {
        transcript.iter().filter(|m| pred(m)).count()
    }

    fn position(transcript: &[GsmMessage], pred: impl Fn(&GsmMessage) -> bool) -> Option<usize> {
        transcript.iter().position(pred)
    }

    // ---- auth_vector: 2G interworking known-answer ------------------------

    #[test]
    fn auth_vector_matches_ts35208_set1_interworking() {
        let av = auth_vector(&hex16(TS1_K), &hex16(TS1_OPC), &hex16(TS1_RAND));
        // Derived by hand from f2/f3/f4 of TS 35.208 test set 1 via
        // TS 33.102 §6.8.1.2 (SRES = XRES halves XORed; Kc = CK/IK halves XORed).
        assert_eq!(av.sres, [0x46, 0xf8, 0x41, 0x6a], "SRES (c2) mismatch");
        assert_eq!(
            av.kc,
            [0xea, 0xe4, 0xbe, 0x82, 0x3a, 0xf9, 0xa0, 0x8b],
            "Kc (c3) mismatch"
        );
        assert_eq!(av.rand, hex16(TS1_RAND));
    }

    #[test]
    fn auth_vector_is_independent_of_sqn_amf_choice() {
        // The triplet uses only f2/f3/f4, which do not read SQN/AMF, so the
        // documented fixed choice cannot change the result. Confirm the values
        // are stable and well-formed regardless.
        let a = auth_vector(&hex16(TS1_K), &hex16(TS1_OPC), &hex16(TS1_RAND));
        let b = auth_vector(&hex16(TS1_K), &hex16(TS1_OPC), &hex16(TS1_RAND));
        assert_eq!(a, b);
    }

    // ---- state machines ---------------------------------------------------

    /// A rogue BTS that out-signals the real one catches the IMSI in cleartext,
    /// and does so without ever authenticating — the whole 2G attack.
    #[test]
    fn rogue_bts_catches_imsi_before_any_auth() {
        let mut bts = Bts {
            plmn_configured: Some(Plmn::new(262, 1, 2)),
            request_imsi: true,
            commanded_cipher: A5::A5_0,
            // A pure catcher holds no keys; it never authenticates.
            auth: None,
            ..Default::default()
        };
        let mut ms = MobileStation {
            imsi: Some(test_imsi()),
            ..Default::default()
        };

        let transcript = drive(&mut bts, &mut ms);

        // The identity leaked...
        assert_eq!(bts.last_imsi_seen, Some(test_imsi()));
        assert_eq!(
            count(&transcript, |m| matches!(
                m,
                GsmMessage::IdentityResponse { imsi: Some(_) }
            )),
            1
        );
        // ...and it leaked with ZERO authentication having run.
        assert_eq!(
            count(&transcript, |m| matches!(
                m,
                GsmMessage::AuthenticationRequest { .. }
            )),
            0
        );
        assert!(!bts.authenticated);
        // The exchange still completed (the phone camped and was accepted).
        assert_eq!(
            count(&transcript, |m| matches!(
                m,
                GsmMessage::LocationUpdateAccept { .. }
            )),
            1
        );
    }

    /// The network commands A5/0 (null encryption) and the MS complies — it has
    /// no mechanism to refuse.
    #[test]
    fn network_commands_a5_0_and_ms_complies() {
        let mut bts = Bts {
            request_imsi: false, // isolate the cipher step
            commanded_cipher: A5::A5_0,
            auth: None,
            ..Default::default()
        };
        let mut ms = MobileStation {
            imsi: Some(test_imsi()),
            ..Default::default()
        };

        let transcript = drive(&mut bts, &mut ms);

        // The network chose null encryption...
        assert_eq!(bts.cipher, Some(A5::A5_0));
        assert_eq!(
            count(&transcript, |m| matches!(
                m,
                GsmMessage::CipherModeCommand {
                    algorithm: A5::A5_0
                }
            )),
            1
        );
        // ...and the phone accepted it and confirmed.
        assert_eq!(ms.cipher, Some(A5::A5_0));
        assert_eq!(
            count(&transcript, |m| matches!(m, GsmMessage::CipherModeComplete)),
            1
        );
    }

    /// With a real triplet the network authenticates the phone, and the phone's
    /// IMSI is still answered before that authentication ever runs — request
    /// order is the point even when auth succeeds.
    #[test]
    fn authenticated_attach_still_leaks_imsi_first() {
        let k = hex16(TS1_K);
        let op_c = hex16(TS1_OPC);
        let av = auth_vector(&k, &op_c, &hex16(TS1_RAND));

        let mut bts = Bts {
            request_imsi: true,
            commanded_cipher: A5::A5_1,
            auth: Some(av),
            assign_tmsi: Some(Tmsi(0xDEAD_BEEF)),
            ..Default::default()
        };
        let mut ms = MobileStation {
            imsi: Some(test_imsi()),
            k: Some(k),
            op_c: Some(op_c),
            ..Default::default()
        };

        let transcript = drive(&mut bts, &mut ms);

        assert!(bts.authenticated, "correct SRES should authenticate");
        assert_eq!(bts.cipher, Some(A5::A5_1));
        assert_eq!(ms.cipher, Some(A5::A5_1));
        assert_eq!(bts.last_imsi_seen, Some(test_imsi()));
        // The TMSI reallocation reached the phone.
        assert_eq!(ms.tmsi, Some(Tmsi(0xDEAD_BEEF)));

        // IdentityResponse strictly precedes AuthenticationRequest.
        let id_resp = position(&transcript, |m| {
            matches!(m, GsmMessage::IdentityResponse { imsi: Some(_) })
        })
        .expect("identity response present");
        let auth_req = position(&transcript, |m| {
            matches!(m, GsmMessage::AuthenticationRequest { .. })
        })
        .expect("auth request present");
        assert!(id_resp < auth_req, "IMSI must be answered before auth");
    }

    /// A wrong subscriber key makes the SRES mismatch, so the network cannot
    /// complete authentication and rejects — but the IMSI already leaked.
    #[test]
    fn wrong_key_fails_auth_and_rejects_but_imsi_already_leaked() {
        let av = auth_vector(&hex16(TS1_K), &hex16(TS1_OPC), &hex16(TS1_RAND));

        let mut bts = Bts {
            request_imsi: true,
            auth: Some(av),
            ..Default::default()
        };
        // MS holds a different key, so its SRES will not match.
        let mut wrong_k = hex16(TS1_K);
        wrong_k[0] ^= 0xff;
        let mut ms = MobileStation {
            imsi: Some(test_imsi()),
            k: Some(wrong_k),
            op_c: Some(hex16(TS1_OPC)),
            ..Default::default()
        };

        let transcript = drive(&mut bts, &mut ms);

        assert!(!bts.authenticated, "wrong SRES must not authenticate");
        assert_eq!(
            count(&transcript, |m| matches!(
                m,
                GsmMessage::LocationUpdateReject { .. }
            )),
            1
        );
        // No cipher was ever negotiated on the rejected path.
        assert_eq!(bts.cipher, None);
        assert_eq!(ms.cipher, None);
        // The catch happened anyway, before auth.
        assert_eq!(bts.last_imsi_seen, Some(test_imsi()));
    }
}
