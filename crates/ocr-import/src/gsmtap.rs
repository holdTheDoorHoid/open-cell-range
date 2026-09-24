//! The GSMTAP version-2 header (the Osmocom "tap" pseudo-header).
//!
//! GSMTAP is a UDP encapsulation used by osmocom tools, `srsRAN`, `SCAT` and
//! others to carry a single decoded radio message together with the physical-layer
//! metadata around it (which ARFCN/EARFCN, which timeslot/channel, uplink or
//! downlink, signal level). Its layout is stable and well documented; the fixed
//! version-2 header is 16 bytes (`hdr_len` = 4 32-bit words):
//!
//! ```text
//!  0               1               2               3
//!  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    version    |   hdr_len     |     type      |   timeslot    |
//! +---------------+---------------+---------------+---------------+
//! |            ARFCN              | signal_dbm    |  snr_db       |
//! +------------------------------+----------------+---------------+
//! |                        frame_number                          |
//! +---------------+---------------+---------------+---------------+
//! |   sub_type    |  antenna_nr   |   sub_slot    |     res       |
//! +---------------+---------------+---------------+---------------+
//! ```
//!
//! Multi-byte fields are big-endian. `ARFCN` carries two flag bits in its top two
//! bits (PCS band, and uplink), with the frequency number in the low 14. This
//! module decodes the header and hands back the message body that follows it; it
//! does **not** decode that body — that is [`crate::l3`]'s job, and only to the
//! message-type level. Every read is bounds-checked; the parser never panics.

use core::fmt;

/// The registered UDP port GSMTAP is sent to.
pub const GSMTAP_UDP_PORT: u16 = 4729;
/// The only GSMTAP version this importer understands.
pub const GSMTAP_VERSION_V2: u8 = 0x02;

// --- GSMTAP payload types (the `type` field) ------------------------------------
/// GSM Um (2G air interface) L2/L3 signalling.
pub const GSMTAP_TYPE_UM: u8 = 0x01;
/// GSM Um burst (raw bits) — not decoded.
pub const GSMTAP_TYPE_UM_BURST: u8 = 0x03;
/// UMTS (3G) RRC — recognised but this project has no 3G engine.
pub const GSMTAP_TYPE_UMTS_RRC: u8 = 0x0c;
/// LTE (4G) RRC — ASN.1/PER encoded; recognised, body not decoded.
pub const GSMTAP_TYPE_LTE_RRC: u8 = 0x0d;
/// LTE (4G) MAC — not decoded.
pub const GSMTAP_TYPE_LTE_MAC: u8 = 0x0e;
/// LTE (4G) NAS (EMM/ESM) — decoded to the message-type level.
pub const GSMTAP_TYPE_LTE_NAS: u8 = 0x12;

// --- GSM Um logical channel (`sub_type` when `type` == UM) ----------------------
pub const GSMTAP_CHANNEL_UNKNOWN: u8 = 0x00;
pub const GSMTAP_CHANNEL_BCCH: u8 = 0x01;
pub const GSMTAP_CHANNEL_CCCH: u8 = 0x02;
pub const GSMTAP_CHANNEL_RACH: u8 = 0x03;
pub const GSMTAP_CHANNEL_AGCH: u8 = 0x04;
pub const GSMTAP_CHANNEL_PCH: u8 = 0x05;
pub const GSMTAP_CHANNEL_SDCCH: u8 = 0x06;
pub const GSMTAP_CHANNEL_SDCCH4: u8 = 0x07;
pub const GSMTAP_CHANNEL_SDCCH8: u8 = 0x08;
/// Bit OR-ed into the channel for the associated control channel (SACCH).
pub const GSMTAP_CHANNEL_ACCH: u8 = 0x80;

// --- LTE NAS sub_type -----------------------------------------------------------
/// A plain (unciphered) NAS message — decodable to the message-type level.
pub const GSMTAP_LTE_NAS_PLAIN: u8 = 0x00;
/// A security-protected NAS message (6-byte security header before the plain msg).
pub const GSMTAP_LTE_NAS_SEC_HDR: u8 = 0x01;

// --- ARFCN flag bits ------------------------------------------------------------
const GSMTAP_ARFCN_MASK: u16 = 0x3fff;
const GSMTAP_ARFCN_F_UPLINK: u16 = 0x4000;
const GSMTAP_ARFCN_F_PCS: u16 = 0x8000;

/// Length of the fixed version-2 GSMTAP header, in bytes.
const V2_HEADER_LEN: usize = 16;

/// A failure decoding the GSMTAP header itself (not the message it carries).
#[derive(Debug, PartialEq, Eq)]
pub enum GsmtapError {
    /// Fewer bytes than the fixed 16-byte version-2 header.
    TooShort { got: usize },
    /// `version` field was not [`GSMTAP_VERSION_V2`].
    UnsupportedVersion(u8),
    /// `hdr_len` (in 32-bit words) is smaller than the fixed header, or the header
    /// it claims runs past the datagram.
    BadHeaderLen { words: u8, available: usize },
}

impl fmt::Display for GsmtapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GsmtapError::TooShort { got } => write!(
                f,
                "gsmtap: {got} bytes is shorter than the 16-byte v2 header"
            ),
            GsmtapError::UnsupportedVersion(v) => {
                write!(f, "gsmtap: unsupported version {v} (only v2 is decoded)")
            }
            GsmtapError::BadHeaderLen { words, available } => write!(
                f,
                "gsmtap: hdr_len {words} words does not fit in {available} bytes"
            ),
        }
    }
}

impl std::error::Error for GsmtapError {}

/// A decoded GSMTAP version-2 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GsmtapHdr {
    pub version: u8,
    /// Header length in 32-bit words (4 for the fixed v2 header).
    pub hdr_len_words: u8,
    /// The payload type — one of the `GSMTAP_TYPE_*` constants.
    pub msg_type: u8,
    pub timeslot: u8,
    /// ARFCN with its two flag bits still set; use [`GsmtapHdr::arfcn`] for the
    /// frequency number and [`GsmtapHdr::is_uplink`] / [`GsmtapHdr::is_pcs`].
    pub arfcn_raw: u16,
    pub signal_dbm: i8,
    pub snr_db: i8,
    pub frame_number: u32,
    /// Meaning depends on `msg_type`: the logical channel for GSM Um, the NAS
    /// plain/secure flag for LTE NAS, the RRC channel for LTE RRC, etc.
    pub sub_type: u8,
    pub antenna_nr: u8,
    pub sub_slot: u8,
    pub res: u8,
    /// The header length actually consumed, in bytes (`hdr_len_words * 4`).
    pub header_len_bytes: usize,
}

impl GsmtapHdr {
    /// The frequency number with the flag bits masked off.
    pub fn arfcn(&self) -> u16 {
        self.arfcn_raw & GSMTAP_ARFCN_MASK
    }

    /// True if the uplink flag is set (message travelled UE -> network).
    pub fn is_uplink(&self) -> bool {
        self.arfcn_raw & GSMTAP_ARFCN_F_UPLINK != 0
    }

    /// True if the PCS-band flag is set.
    pub fn is_pcs(&self) -> bool {
        self.arfcn_raw & GSMTAP_ARFCN_F_PCS != 0
    }

    /// Parse the header from the start of a UDP payload, returning the header and
    /// the message body that follows it (`&payload[header_len_bytes..]`).
    pub fn parse(payload: &[u8]) -> Result<(GsmtapHdr, &[u8]), GsmtapError> {
        let fixed = payload
            .get(0..V2_HEADER_LEN)
            .ok_or(GsmtapError::TooShort { got: payload.len() })?;
        let version = fixed[0];
        if version != GSMTAP_VERSION_V2 {
            return Err(GsmtapError::UnsupportedVersion(version));
        }
        let hdr_len_words = fixed[1];
        let header_len_bytes = hdr_len_words as usize * 4;
        // The declared header must be at least the fixed 16 bytes and must fit.
        if header_len_bytes < V2_HEADER_LEN || header_len_bytes > payload.len() {
            return Err(GsmtapError::BadHeaderLen {
                words: hdr_len_words,
                available: payload.len(),
            });
        }
        let hdr = GsmtapHdr {
            version,
            hdr_len_words,
            msg_type: fixed[2],
            timeslot: fixed[3],
            arfcn_raw: u16::from_be_bytes([fixed[4], fixed[5]]),
            signal_dbm: fixed[6] as i8,
            snr_db: fixed[7] as i8,
            frame_number: u32::from_be_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]),
            sub_type: fixed[12],
            antenna_nr: fixed[13],
            sub_slot: fixed[14],
            res: fixed[15],
            header_len_bytes,
        };
        // Body is whatever follows the (possibly extended) header. The slice is
        // in-bounds because header_len_bytes <= payload.len() was checked above.
        let body = &payload[header_len_bytes..];
        Ok((hdr, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr_bytes(gtype: u8, arfcn: u16, sub_type: u8) -> Vec<u8> {
        let mut g = vec![0x02, 0x04, gtype, 0x00];
        g.extend_from_slice(&arfcn.to_be_bytes());
        g.extend_from_slice(&[0x00, 0x00]); // signal, snr
        g.extend_from_slice(&0u32.to_be_bytes()); // frame number
        g.extend_from_slice(&[sub_type, 0x00, 0x00, 0x00]);
        g
    }

    #[test]
    fn parses_fixed_header_and_splits_body() {
        let mut buf = hdr_bytes(
            GSMTAP_TYPE_UM,
            GSMTAP_ARFCN_F_UPLINK | 871,
            GSMTAP_CHANNEL_SDCCH,
        );
        buf.extend_from_slice(&[0xaa, 0xbb]);
        let (hdr, body) = GsmtapHdr::parse(&buf).expect("parse");
        assert_eq!(hdr.msg_type, GSMTAP_TYPE_UM);
        assert_eq!(hdr.arfcn(), 871);
        assert!(hdr.is_uplink());
        assert_eq!(hdr.sub_type, GSMTAP_CHANNEL_SDCCH);
        assert_eq!(hdr.header_len_bytes, 16);
        assert_eq!(body, &[0xaa, 0xbb]);
    }

    #[test]
    fn rejects_short_header() {
        assert!(matches!(
            GsmtapHdr::parse(&[0x02, 0x04, 0x01]),
            Err(GsmtapError::TooShort { .. })
        ));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut buf = hdr_bytes(GSMTAP_TYPE_UM, 1, 0);
        buf[0] = 0x01;
        assert!(matches!(
            GsmtapHdr::parse(&buf),
            Err(GsmtapError::UnsupportedVersion(0x01))
        ));
    }

    #[test]
    fn rejects_header_len_that_overruns() {
        let mut buf = hdr_bytes(GSMTAP_TYPE_UM, 1, 0);
        buf[1] = 0xff; // claims 255 words of header
        assert!(matches!(
            GsmtapHdr::parse(&buf),
            Err(GsmtapError::BadHeaderLen { .. })
        ));
    }

    #[test]
    fn extended_header_len_skips_extra_words() {
        // hdr_len = 5 words = 20 bytes; 4 extra bytes before the body.
        let mut buf = hdr_bytes(GSMTAP_TYPE_LTE_NAS, 1, GSMTAP_LTE_NAS_PLAIN);
        buf[1] = 0x05;
        buf.extend_from_slice(&[0, 0, 0, 0]); // the extra header word
        buf.extend_from_slice(&[0x07, 0x55]); // the body
        let (hdr, body) = GsmtapHdr::parse(&buf).expect("parse");
        assert_eq!(hdr.header_len_bytes, 20);
        assert_eq!(body, &[0x07, 0x55]);
    }
}
