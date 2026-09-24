//! Mapping a GSMTAP record to the closest [`ocr_air::AirEvent`] the engine models.
//!
//! This is where the honesty line of the whole importer sits. The engine's
//! [`ocr_air::Payload`] is a union of *fully decoded* per-generation messages; it
//! has no "raw bytes" variant. GSMTAP hands us a header plus an L3/NAS message
//! body. We decode that body **only to the message-type level** — the protocol
//! discriminator and message-type octets, plus the one or two fixed mandatory
//! octets that define the message's security-relevant meaning (an identity type, a
//! reject cause, a selected algorithm). We deliberately do **not** decode variable
//! information elements, ASN.1/PER RRC, IMSI/GUTI digit strings, or the RAND/AUTN
//! cryptographic material. Where a `Payload` variant would require content we do
//! not decode, we do **not** invent it: the record is reported as a
//! [`SkipReason`], counted, and dropped, rather than faked.
//!
//! ## What is recognised
//!
//! | GSMTAP type | mapped to | how |
//! |-------------|-----------|-----|
//! | `UM` (2G)   | [`ocr_gsm::GsmMessage`] subset | GSM L3 PD + message type |
//! | `LTE_NAS`   | [`ocr_lte::LteNasMessage`] subset | EMM message type |
//! | `LTE_RRC`   | — | recognised, ASN.1 body not decoded (future work) |
//! | `UMTS_RRC`  | — | recognised, but there is no 3G engine in this project |
//! | other       | — | unknown / not decoded |
//!
//! ### GSM Um (`GSMTAP_TYPE_UM`)
//! The body is treated as a GSM L3 signalling message beginning at the protocol
//! discriminator (PD) octet. LAPDm / L2 framing and the CCCH pseudo-length octet
//! are **not** stripped — a producer that includes them would need that handled
//! first (a clean extension point). Decoded message types:
//! - MM Identity Request (`0x18`) -> `IdentityRequest { id_type }`
//! - MM Location Updating Reject (`0x04`) -> `LocationUpdateReject { cause }`
//! - RR Ciphering Mode Command (`0x35`) -> `CipherModeCommand { algorithm }`
//!
//! ### LTE NAS (`GSMTAP_TYPE_LTE_NAS`)
//! Only *plain* EMM messages are decoded (the `sub_type` PLAIN flag, or a
//! security-protected message whose inner plain header we can see past the 6-byte
//! security header). Ciphered messages are skipped. Decoded EMM message types:
//! - Identity Request (`0x55`) -> `IdentityRequest`
//! - Attach Reject (`0x44`) -> `AttachReject { cause }`
//! - Tracking Area Update Reject (`0x4b`) -> `TrackingAreaUpdateReject { cause }`
//! - Security Mode Command (`0x5d`) -> `SecurityModeCommand { algorithm }`
//! - Authentication Failure (`0x5c`) -> MAC-failure / synch-failure variants
//!
//! ### Fields not reconstructable from the header (documented gaps)
//! `SystemInformation` (needs the full SIB: PLMN/LAC/TAC/cell id), `AttachRequest`
//! (needs the GUTI), `AuthenticationRequest`/`AuthenticationResponse` (RAND/AUTN/RES
//! cryptographic content), `IdentityResponse` (the IMSI digits), NR NAS/RRC of any
//! kind (no GSMTAP NR type is decoded here), and LTE Paging (an RRC-borne record,
//! not an EMM NAS message) are all left as gaps: recognised where possible, never
//! fabricated. Full NAS decode, and QMDL / SCAT / QCSuper container formats, are
//! future work — see the crate docs.

use core::fmt;

use ocr_air::{Direction, Payload, Rat};
use ocr_gsm::{GsmMessage, IdentityType, A5};
use ocr_lte::{LteNasMessage, NasAlgorithm};

use crate::gsmtap::{self, GsmtapHdr};

/// Why a GSMTAP record did not become an `AirEvent`. Reported and counted by the
/// importer so coverage gaps are visible rather than silent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// Not a UDP datagram on the GSMTAP port.
    NotGsmtap,
    /// The GSMTAP header itself failed to parse.
    BadGsmtapHeader,
    /// A generation we recognise but cannot map to an engine message.
    RecognisedButUndecoded { gsmtap_type: u8, what: &'static str },
    /// A GSMTAP payload type this importer does not recognise.
    UnknownGsmtapType(u8),
    /// A GSM L3 message whose PD / message type we do not map.
    UnmappedGsm { pd: u8, msg_type: u8 },
    /// An LTE NAS (EMM) message type we do not map.
    UnmappedLteNas(u8),
    /// The NAS message is security-ciphered, so its type cannot be read.
    CipheredNas,
    /// A recognised message carried a value the engine does not model
    /// (e.g. A5/2, a mixed EEA/EIA pair, an unmodelled identity type).
    OutsideEngineModel(&'static str),
    /// The L3 / NAS body was too short for the fields the message type requires.
    TooShort(&'static str),
}

impl SkipReason {
    /// A short, stable grouping label for the import summary (many records may
    /// share one category).
    pub fn category(&self) -> &'static str {
        match self {
            SkipReason::NotGsmtap => "not a GSMTAP datagram",
            SkipReason::BadGsmtapHeader => "malformed GSMTAP header",
            SkipReason::RecognisedButUndecoded { .. } => "recognised but not decoded",
            SkipReason::UnknownGsmtapType(_) => "unknown GSMTAP type",
            SkipReason::UnmappedGsm { .. } => "unmapped GSM L3 message",
            SkipReason::UnmappedLteNas(_) => "unmapped LTE NAS message",
            SkipReason::CipheredNas => "ciphered NAS message",
            SkipReason::OutsideEngineModel(_) => "value outside engine model",
            SkipReason::TooShort(_) => "truncated message body",
        }
    }
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SkipReason::NotGsmtap => write!(f, "not a UDP datagram on the GSMTAP port"),
            SkipReason::BadGsmtapHeader => write!(f, "GSMTAP header failed to parse"),
            SkipReason::RecognisedButUndecoded { gsmtap_type, what } => write!(
                f,
                "GSMTAP type {gsmtap_type:#04x} recognised but not decoded ({what})"
            ),
            SkipReason::UnknownGsmtapType(t) => write!(f, "unknown GSMTAP type {t:#04x}"),
            SkipReason::UnmappedGsm { pd, msg_type } => write!(
                f,
                "GSM L3 message not mapped (PD {pd:#04x}, type {msg_type:#04x})"
            ),
            SkipReason::UnmappedLteNas(t) => {
                write!(f, "LTE NAS/EMM message type {t:#04x} not mapped")
            }
            SkipReason::CipheredNas => write!(f, "NAS message is ciphered; type unreadable"),
            SkipReason::OutsideEngineModel(what) => {
                write!(f, "value outside the engine's model ({what})")
            }
            SkipReason::TooShort(what) => write!(f, "message body too short for {what}"),
        }
    }
}

/// A GSMTAP record successfully mapped onto the engine's air model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapped {
    pub rat: Rat,
    pub dir: Direction,
    pub payload: Payload,
}

/// Best-effort direction from the ARFCN uplink flag. GSMTAP does not always carry
/// direction, so this is advisory (the monitor keys on cell id, not direction).
fn direction_of(hdr: &GsmtapHdr) -> Direction {
    if hdr.is_uplink() {
        Direction::UeToNet
    } else {
        Direction::NetToUe
    }
}

/// Map a parsed GSMTAP header + message body to the closest `AirEvent` payload.
pub fn map(hdr: &GsmtapHdr, body: &[u8]) -> Result<Mapped, SkipReason> {
    match hdr.msg_type {
        gsmtap::GSMTAP_TYPE_UM => {
            let payload = map_gsm_l3(body)?;
            Ok(Mapped {
                rat: Rat::Gsm,
                dir: direction_of(hdr),
                payload,
            })
        }
        gsmtap::GSMTAP_TYPE_LTE_NAS => {
            let payload = map_lte_nas(hdr, body)?;
            Ok(Mapped {
                rat: Rat::Lte,
                dir: direction_of(hdr),
                payload,
            })
        }
        gsmtap::GSMTAP_TYPE_LTE_RRC => Err(SkipReason::RecognisedButUndecoded {
            gsmtap_type: hdr.msg_type,
            what: "LTE RRC is ASN.1/PER encoded; body decode is future work",
        }),
        gsmtap::GSMTAP_TYPE_LTE_MAC => Err(SkipReason::RecognisedButUndecoded {
            gsmtap_type: hdr.msg_type,
            what: "LTE MAC is not modelled by the engine",
        }),
        gsmtap::GSMTAP_TYPE_UMTS_RRC => Err(SkipReason::RecognisedButUndecoded {
            gsmtap_type: hdr.msg_type,
            what: "no 3G/UMTS engine in this project",
        }),
        gsmtap::GSMTAP_TYPE_UM_BURST => Err(SkipReason::RecognisedButUndecoded {
            gsmtap_type: hdr.msg_type,
            what: "raw Um bursts carry no decoded L3",
        }),
        other => Err(SkipReason::UnknownGsmtapType(other)),
    }
}

// ---------------------------------------------------------------------------
// GSM Um L3 (TS 24.007 / 24.008 / 44.018), message-type level only.
// ---------------------------------------------------------------------------

const GSM_PD_MM: u8 = 0x05;
const GSM_PD_RR: u8 = 0x06;

const MM_LOCATION_UPDATING_REJECT: u8 = 0x04;
const MM_IDENTITY_REQUEST: u8 = 0x18;
const RR_CIPHERING_MODE_COMMAND: u8 = 0x35;

fn map_gsm_l3(body: &[u8]) -> Result<Payload, SkipReason> {
    let octet0 = *body
        .first()
        .ok_or(SkipReason::TooShort("GSM L3 PD octet"))?;
    let pd = octet0 & 0x0f;
    let raw_mt = *body
        .get(1)
        .ok_or(SkipReason::TooShort("GSM L3 message type"))?;

    match pd {
        GSM_PD_MM => {
            // For MM/CC the message type is the low 6 bits (top two bits carry a
            // send-sequence number / spare in some messages).
            let mt = raw_mt & 0x3f;
            match mt {
                MM_IDENTITY_REQUEST => {
                    let id_octet = *body
                        .get(2)
                        .ok_or(SkipReason::TooShort("MM Identity Request id type"))?;
                    // TS 24.008 §10.5.1.4: identity type is the low 3 bits.
                    let id_type = match id_octet & 0x07 {
                        1 => IdentityType::Imsi,
                        2 => IdentityType::Imei,
                        4 => IdentityType::Tmsi,
                        _ => return Err(SkipReason::OutsideEngineModel("GSM identity type")),
                    };
                    Ok(Payload::Gsm(GsmMessage::IdentityRequest { id_type }))
                }
                MM_LOCATION_UPDATING_REJECT => {
                    let cause = *body
                        .get(2)
                        .ok_or(SkipReason::TooShort("MM Location Updating Reject cause"))?;
                    Ok(Payload::Gsm(GsmMessage::LocationUpdateReject { cause }))
                }
                _ => Err(SkipReason::UnmappedGsm {
                    pd,
                    msg_type: raw_mt,
                }),
            }
        }
        GSM_PD_RR => match raw_mt {
            RR_CIPHERING_MODE_COMMAND => {
                let setting = *body
                    .get(2)
                    .ok_or(SkipReason::TooShort("RR Ciphering Mode Setting"))?;
                // TS 44.018 §10.5.2.9: bit 1 (0x01) is SC (start ciphering); when
                // clear, no ciphering (A5/0). When set, bits 2-4 select the
                // algorithm: 0 -> A5/1, 1 -> A5/2, 2 -> A5/3.
                let algorithm = if setting & 0x01 == 0 {
                    A5::A5_0
                } else {
                    match (setting >> 1) & 0x07 {
                        0 => A5::A5_1,
                        2 => A5::A5_3,
                        _ => return Err(SkipReason::OutsideEngineModel("GSM A5 algorithm")),
                    }
                };
                Ok(Payload::Gsm(GsmMessage::CipherModeCommand { algorithm }))
            }
            _ => Err(SkipReason::UnmappedGsm {
                pd,
                msg_type: raw_mt,
            }),
        },
        _ => Err(SkipReason::UnmappedGsm {
            pd,
            msg_type: raw_mt,
        }),
    }
}

// ---------------------------------------------------------------------------
// LTE NAS / EMM (TS 24.301), message-type level only.
// ---------------------------------------------------------------------------

const EMM_PD: u8 = 0x07;
const ESM_PD: u8 = 0x02;
/// Bytes of security header (message auth code + sequence number) before the inner
/// plain message in a security-protected NAS PDU.
const NAS_SEC_HEADER_LEN: usize = 6;

const EMM_ATTACH_REJECT: u8 = 0x44;
const EMM_TAU_REJECT: u8 = 0x4b;
const EMM_AUTHENTICATION_FAILURE: u8 = 0x5c;
const EMM_IDENTITY_REQUEST: u8 = 0x55;
const EMM_SECURITY_MODE_COMMAND: u8 = 0x5d;

/// EMM cause values used by Authentication Failure (TS 24.301 §9.9.3.9).
const EMM_CAUSE_MAC_FAILURE: u8 = 20;
const EMM_CAUSE_SYNCH_FAILURE: u8 = 21;

fn map_lte_nas(hdr: &GsmtapHdr, body: &[u8]) -> Result<Payload, SkipReason> {
    // Find the plain EMM message. If the sub_type says plain, or the first octet's
    // security-header-type nibble is 0, it starts at offset 0. Otherwise it is a
    // security-protected PDU: past the 6-byte security header we may still see the
    // inner plain header (an integrity-protected but unciphered message); if not,
    // it is ciphered and unreadable.
    let first = *body.first().ok_or(SkipReason::TooShort("NAS PDU"))?;
    let sec_hdr_type = first >> 4;
    let plain: &[u8] = if hdr.sub_type == gsmtap::GSMTAP_LTE_NAS_PLAIN || sec_hdr_type == 0 {
        body
    } else {
        let inner = body
            .get(NAS_SEC_HEADER_LEN..)
            .ok_or(SkipReason::TooShort("NAS security header"))?;
        match inner.first() {
            Some(o) if o & 0x0f == EMM_PD => inner,
            _ => return Err(SkipReason::CipheredNas),
        }
    };

    let octet0 = *plain.first().ok_or(SkipReason::TooShort("EMM PD"))?;
    let pd = octet0 & 0x0f;
    if pd == ESM_PD {
        return Err(SkipReason::UnmappedLteNas(0x00)); // ESM not modelled
    }
    if pd != EMM_PD {
        return Err(SkipReason::CipheredNas);
    }
    let mt = *plain
        .get(1)
        .ok_or(SkipReason::TooShort("EMM message type"))?;

    match mt {
        EMM_IDENTITY_REQUEST => Ok(Payload::LteNas(LteNasMessage::IdentityRequest)),
        EMM_ATTACH_REJECT => {
            let cause = *plain
                .get(2)
                .ok_or(SkipReason::TooShort("EMM Attach Reject cause"))?;
            Ok(Payload::LteNas(LteNasMessage::AttachReject { cause }))
        }
        EMM_TAU_REJECT => {
            let cause = *plain
                .get(2)
                .ok_or(SkipReason::TooShort("EMM TAU Reject cause"))?;
            Ok(Payload::LteNas(LteNasMessage::TrackingAreaUpdateReject {
                cause,
            }))
        }
        EMM_SECURITY_MODE_COMMAND => {
            // The NAS security algorithms IE: high nibble = ciphering (EEA), low
            // nibble = integrity (EIA). The engine models only the matched pairs.
            let algs = *plain
                .get(2)
                .ok_or(SkipReason::TooShort("EMM Security Mode Command algorithms"))?;
            let algorithm = match algs {
                0x00 => NasAlgorithm::EEA0_EIA0,
                0x11 => NasAlgorithm::EEA1_EIA1,
                0x22 => NasAlgorithm::EEA2_EIA2,
                _ => return Err(SkipReason::OutsideEngineModel("LTE EEA/EIA pair")),
            };
            Ok(Payload::LteNas(LteNasMessage::SecurityModeCommand {
                algorithm,
            }))
        }
        EMM_AUTHENTICATION_FAILURE => {
            let cause = *plain
                .get(2)
                .ok_or(SkipReason::TooShort("EMM Authentication Failure cause"))?;
            match cause {
                EMM_CAUSE_MAC_FAILURE => Ok(Payload::LteNas(
                    LteNasMessage::AuthenticationFailureMacFailure,
                )),
                EMM_CAUSE_SYNCH_FAILURE => {
                    // Optional AUTS is a TLV (tag 0x30, length, value). Parse it if
                    // present; the monitor only keys on the variant, so an absent
                    // AUTS is tolerated as an empty value rather than faked.
                    let auts = parse_optional_tlv(plain.get(3..), 0x30).unwrap_or_default();
                    Ok(Payload::LteNas(
                        LteNasMessage::AuthenticationFailureSyncFailure { auts },
                    ))
                }
                _ => Err(SkipReason::OutsideEngineModel(
                    "EMM authentication-failure cause",
                )),
            }
        }
        other => Err(SkipReason::UnmappedLteNas(other)),
    }
}

/// Parse a single optional type-length-value IE with the given tag from the front
/// of `rest`. Returns the value bytes if the tag matches and the length fits.
fn parse_optional_tlv(rest: Option<&[u8]>, tag: u8) -> Option<Vec<u8>> {
    let rest = rest?;
    if *rest.first()? != tag {
        return None;
    }
    let len = *rest.get(1)? as usize;
    let value = rest.get(2..2 + len)?;
    Some(value.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ocr_lte::LteNasMessage;

    fn hdr(gtype: u8, sub_type: u8, uplink: bool) -> GsmtapHdr {
        GsmtapHdr {
            version: 2,
            hdr_len_words: 4,
            msg_type: gtype,
            timeslot: 0,
            arfcn_raw: if uplink { 0x4000 } else { 0 },
            signal_dbm: 0,
            snr_db: 0,
            frame_number: 0,
            sub_type,
            antenna_nr: 0,
            sub_slot: 0,
            res: 0,
            header_len_bytes: 16,
        }
    }

    #[test]
    fn gsm_identity_request_imsi() {
        let h = hdr(gsmtap::GSMTAP_TYPE_UM, gsmtap::GSMTAP_CHANNEL_SDCCH, false);
        let m = map(&h, &[0x05, 0x18, 0x01]).expect("map");
        assert_eq!(m.rat, Rat::Gsm);
        assert_eq!(m.dir, Direction::NetToUe);
        assert_eq!(
            m.payload,
            Payload::Gsm(GsmMessage::IdentityRequest {
                id_type: IdentityType::Imsi
            })
        );
    }

    #[test]
    fn gsm_identity_request_carries_sequence_bits() {
        // Some producers set the send-sequence bits in the MM message-type octet.
        let h = hdr(gsmtap::GSMTAP_TYPE_UM, gsmtap::GSMTAP_CHANNEL_SDCCH, true);
        let m = map(&h, &[0x05, 0x40 | 0x18, 0x04]).expect("map"); // TMSI id type
        assert_eq!(m.dir, Direction::UeToNet);
        assert_eq!(
            m.payload,
            Payload::Gsm(GsmMessage::IdentityRequest {
                id_type: IdentityType::Tmsi
            })
        );
    }

    #[test]
    fn gsm_cipher_mode_a5_variants() {
        let h = hdr(gsmtap::GSMTAP_TYPE_UM, gsmtap::GSMTAP_CHANNEL_SDCCH, false);
        // SC=0 -> A5/0.
        assert_eq!(
            map(&h, &[0x06, 0x35, 0x00]).unwrap().payload,
            Payload::Gsm(GsmMessage::CipherModeCommand {
                algorithm: A5::A5_0
            })
        );
        // SC=1, alg field 0 -> A5/1.
        assert_eq!(
            map(&h, &[0x06, 0x35, 0x01]).unwrap().payload,
            Payload::Gsm(GsmMessage::CipherModeCommand {
                algorithm: A5::A5_1
            })
        );
        // SC=1, alg field 2 -> A5/3.
        assert_eq!(
            map(&h, &[0x06, 0x35, 0x05]).unwrap().payload,
            Payload::Gsm(GsmMessage::CipherModeCommand {
                algorithm: A5::A5_3
            })
        );
        // SC=1, alg field 1 -> A5/2 is not modelled.
        assert_eq!(
            map(&h, &[0x06, 0x35, 0x03]),
            Err(SkipReason::OutsideEngineModel("GSM A5 algorithm"))
        );
    }

    #[test]
    fn gsm_location_updating_reject() {
        let h = hdr(gsmtap::GSMTAP_TYPE_UM, gsmtap::GSMTAP_CHANNEL_SDCCH, false);
        assert_eq!(
            map(&h, &[0x05, 0x04, 0x0f]).unwrap().payload,
            Payload::Gsm(GsmMessage::LocationUpdateReject { cause: 0x0f })
        );
    }

    #[test]
    fn gsm_unmapped_message_is_reported() {
        let h = hdr(gsmtap::GSMTAP_TYPE_UM, gsmtap::GSMTAP_CHANNEL_SDCCH, false);
        // MM Authentication Request (0x12): recognised generation, not mapped.
        assert!(matches!(
            map(&h, &[0x05, 0x12, 0x00]),
            Err(SkipReason::UnmappedGsm { .. })
        ));
    }

    #[test]
    fn gsm_truncated_body() {
        let h = hdr(gsmtap::GSMTAP_TYPE_UM, gsmtap::GSMTAP_CHANNEL_SDCCH, false);
        assert!(matches!(map(&h, &[0x05]), Err(SkipReason::TooShort(_))));
    }

    #[test]
    fn lte_nas_plain_identity_request() {
        let h = hdr(
            gsmtap::GSMTAP_TYPE_LTE_NAS,
            gsmtap::GSMTAP_LTE_NAS_PLAIN,
            false,
        );
        let m = map(&h, &[0x07, 0x55]).expect("map");
        assert_eq!(m.rat, Rat::Lte);
        assert_eq!(m.payload, Payload::LteNas(LteNasMessage::IdentityRequest));
    }

    #[test]
    fn lte_nas_reject_and_smc_and_failures() {
        let h = hdr(
            gsmtap::GSMTAP_TYPE_LTE_NAS,
            gsmtap::GSMTAP_LTE_NAS_PLAIN,
            false,
        );
        assert_eq!(
            map(&h, &[0x07, 0x44, 0x0b]).unwrap().payload,
            Payload::LteNas(LteNasMessage::AttachReject { cause: 0x0b })
        );
        assert_eq!(
            map(&h, &[0x07, 0x4b, 0x09]).unwrap().payload,
            Payload::LteNas(LteNasMessage::TrackingAreaUpdateReject { cause: 0x09 })
        );
        assert_eq!(
            map(&h, &[0x07, 0x5d, 0x00]).unwrap().payload,
            Payload::LteNas(LteNasMessage::SecurityModeCommand {
                algorithm: NasAlgorithm::EEA0_EIA0
            })
        );
        assert_eq!(
            map(&h, &[0x07, 0x5c, 20]).unwrap().payload,
            Payload::LteNas(LteNasMessage::AuthenticationFailureMacFailure)
        );
        // Synch failure with an AUTS TLV (tag 0x30, len 14).
        let mut sync = vec![0x07, 0x5c, 21, 0x30, 14];
        sync.extend_from_slice(&[0xab; 14]);
        assert_eq!(
            map(&h, &sync).unwrap().payload,
            Payload::LteNas(LteNasMessage::AuthenticationFailureSyncFailure {
                auts: vec![0xab; 14]
            })
        );
    }

    #[test]
    fn lte_nas_ciphered_is_skipped() {
        // Security-protected NAS (sec hdr type 2) whose inner PDU is ciphered.
        let h = hdr(
            gsmtap::GSMTAP_TYPE_LTE_NAS,
            gsmtap::GSMTAP_LTE_NAS_SEC_HDR,
            false,
        );
        // octet0 = 0x27 (sec hdr type 2, PD EMM), then MAC(4)+seq(1), then junk.
        let pdu = [0x27, 1, 2, 3, 4, 5, 0xff, 0xff];
        assert_eq!(map(&h, &pdu), Err(SkipReason::CipheredNas));
    }

    #[test]
    fn lte_nas_integrity_protected_but_readable() {
        // Sec hdr type 1 (integrity only): inner plain header visible past 6 bytes.
        let h = hdr(
            gsmtap::GSMTAP_TYPE_LTE_NAS,
            gsmtap::GSMTAP_LTE_NAS_SEC_HDR,
            false,
        );
        let pdu = [0x17, 1, 2, 3, 4, 5, 0x07, 0x55];
        assert_eq!(
            map(&h, &pdu).unwrap().payload,
            Payload::LteNas(LteNasMessage::IdentityRequest)
        );
    }

    #[test]
    fn lte_rrc_recognised_but_undecoded() {
        let h = hdr(gsmtap::GSMTAP_TYPE_LTE_RRC, 0, false);
        assert!(matches!(
            map(&h, &[0xde, 0xad]),
            Err(SkipReason::RecognisedButUndecoded { .. })
        ));
    }

    #[test]
    fn unknown_gsmtap_type() {
        let h = hdr(0x7f, 0, false);
        assert_eq!(map(&h, &[0x00]), Err(SkipReason::UnknownGsmtapType(0x7f)));
    }

    #[test]
    fn skip_reason_categories_are_stable() {
        assert_eq!(SkipReason::CipheredNas.category(), "ciphered NAS message");
        assert_eq!(SkipReason::NotGsmtap.category(), "not a GSMTAP datagram");
    }
}
