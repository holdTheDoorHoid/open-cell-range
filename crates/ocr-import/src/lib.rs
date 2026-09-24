//! Turn a **real capture** into the engine's [`ocr_air::AirEvent`] stream, so the
//! same passive [`ocr_detect::Monitor`] that analyses the browser simulation can
//! analyse captured air. This is the "phase two" seam `DESIGN.md` section 3
//! designs for: importers land here without touching the engines.
//!
//! # Formats
//!
//! Two are supported today, auto-detected from the first bytes of the file (see
//! [`detect_format`]):
//!
//! - **Native NDJSON** ([`ndjson`]) — the simulator's own capture format, exactly
//!   the shape `ocr record` writes and `ocr replay` reads. Every line is a fully
//!   decoded message, so it maps to an `AirEvent` losslessly. This module now owns
//!   that format; `ocr-cli` re-exports it.
//! - **GSMTAP-over-pcap** ([`pcap`] + [`gsmtap`]) — the classic libpcap savefile
//!   format carrying GSMTAP UDP datagrams (osmocom / srsRAN / SCAT style). The
//!   pcap framing, Ethernet/IPv4/UDP wrapping, and the GSMTAP v2 header are parsed
//!   in full; the L3/NAS message inside is decoded **only to the message-type
//!   level** by [`l3`].
//!
//! # Coverage and honest gaps
//!
//! The engine's [`ocr_air::Payload`] is a union of *fully decoded* messages with
//! no raw-bytes variant, so a GSMTAP record only becomes an `AirEvent` when its
//! message type maps to an engine variant whose fields are reconstructable from
//! header-level decoding. Everything else is reported as a [`SkipReason`], counted,
//! and dropped — never fabricated. What is recognised:
//!
//! - **GSM Um** (`GSMTAP_TYPE_UM`): MM Identity Request, MM Location Updating
//!   Reject, RR Ciphering Mode Command.
//! - **LTE NAS** (`GSMTAP_TYPE_LTE_NAS`, plain EMM): Identity Request, Attach
//!   Reject, Tracking Area Update Reject, Security Mode Command, Authentication
//!   Failure (MAC / synch).
//! - **LTE RRC / LTE MAC / UMTS RRC**: recognised (so the generation is known) but
//!   not decoded — ASN.1/PER RRC decode, and any 3G modelling, are out of scope.
//!
//! Gaps left deliberately rather than faked: `SystemInformation` (needs the full
//! SIB), `AttachRequest` (needs the GUTI), `AuthenticationRequest`/`Response`
//! (RAND/AUTN/RES content), `IdentityResponse` (the IMSI digits), all NR NAS/RRC,
//! and LTE paging. **Full NAS decode, and the QMDL / SCAT / QCSuper container
//! formats, are future work.** The GSM Um path also assumes the body starts at the
//! L3 PD octet: LAPDm/L2 framing and the CCCH pseudo-length are not stripped.
//!
//! # Adding a format or extending coverage
//!
//! 1. A new **container** (e.g. QMDL): add a module that yields `(ts_us, rat, dir,
//!    payload)` tuples, add a [`Format`] variant, teach [`detect_format`] its magic,
//!    and dispatch it in [`import_bytes`]. The engines and the CLI are untouched.
//! 2. A new **link type** for pcap: add one arm to [`net::udp_payload`].
//! 3. A new **message type**: add one arm to [`l3::map`] (or its GSM / LTE NAS
//!    helpers). Decode only to the level you can do faithfully; if a field cannot be
//!    reconstructed, return a [`SkipReason`] rather than inventing it.
//!
//! # Robustness
//!
//! Every parser here is **total**: all reads are bounds-checked and malformed input
//! yields an [`Err`] (structural problems) or a [`SkipReason`] (a record that is
//! simply not mappable), never a panic. The crate is intended to be fuzzed.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::Path;

use ocr_air::{AirEvent, CellId};

pub mod gsmtap;
pub mod l3;
pub mod ndjson;
pub mod net;
pub mod pcap;

pub use l3::SkipReason;

/// Which on-disk format a capture is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Classic libpcap savefile carrying GSMTAP UDP datagrams.
    GsmtapPcap,
    /// The simulator's native newline-delimited JSON.
    Ndjson,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Format::GsmtapPcap => write!(f, "GSMTAP pcap"),
            Format::Ndjson => write!(f, "NDJSON"),
        }
    }
}

/// A capture load failure.
#[derive(Debug)]
pub enum ImportError {
    /// The file could not be read.
    Io(std::io::Error),
    /// The pcap container was structurally broken.
    Pcap(pcap::PcapError),
    /// A native NDJSON line failed to parse.
    Ndjson(ndjson::NdjsonError),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportError::Io(e) => write!(f, "I/O error: {e}"),
            ImportError::Pcap(e) => write!(f, "{e}"),
            ImportError::Ndjson(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ImportError {}

impl From<std::io::Error> for ImportError {
    fn from(e: std::io::Error) -> Self {
        ImportError::Io(e)
    }
}

impl From<pcap::PcapError> for ImportError {
    fn from(e: pcap::PcapError) -> Self {
        ImportError::Pcap(e)
    }
}

impl From<ndjson::NdjsonError> for ImportError {
    fn from(e: ndjson::NdjsonError) -> Self {
        ImportError::Ndjson(e)
    }
}

/// The result of importing a capture: the reconstructed `AirEvent` stream, plus a
/// count of what mapped and what was skipped (so coverage gaps are visible).
#[derive(Debug, Clone)]
pub struct Import {
    /// The detected format.
    pub format: Format,
    /// The reconstructed air events, in capture order, with `t_us` normalised so
    /// the first event is at zero (a pcap's absolute epoch timestamps are rebased).
    pub events: Vec<AirEvent>,
    /// Total records considered (pcap packets, or NDJSON lines).
    pub records_total: usize,
    /// Records that became `AirEvent`s (`== events.len()`).
    pub records_mapped: usize,
    /// Per-record reasons for the records that were recognised but not mapped.
    /// Empty for NDJSON (every line maps).
    pub skips: Vec<SkipReason>,
}

impl Import {
    /// Records skipped (recognised but not turned into an `AirEvent`).
    pub fn records_skipped(&self) -> usize {
        self.skips.len()
    }
}

/// Sniff the format from a byte prefix. NDJSON is the default; a classic-pcap magic
/// number in the first four bytes selects the pcap path. (NDJSON always begins with
/// `{`, never a pcap magic, so this never misfires.)
pub fn detect_format(bytes: &[u8]) -> Format {
    if pcap::Pcap::parse(bytes).is_ok() {
        Format::GsmtapPcap
    } else {
        Format::Ndjson
    }
}

/// Read a capture file, auto-detecting its format, and reconstruct the events.
pub fn import_path(path: impl AsRef<Path>) -> Result<Import, ImportError> {
    let bytes = std::fs::read(path)?;
    import_bytes(&bytes)
}

/// Import a capture from an in-memory byte buffer, auto-detecting its format.
pub fn import_bytes(bytes: &[u8]) -> Result<Import, ImportError> {
    match detect_format(bytes) {
        Format::GsmtapPcap => import_gsmtap_pcap(bytes),
        Format::Ndjson => import_ndjson(bytes),
    }
}

/// Import the native NDJSON format. Every line is already a decoded message, so
/// there are no skips.
fn import_ndjson(bytes: &[u8]) -> Result<Import, ImportError> {
    let events = ndjson::read_events(bytes)?;
    let n = events.len();
    Ok(Import {
        format: Format::Ndjson,
        events,
        records_total: n,
        records_mapped: n,
        skips: Vec::new(),
    })
}

/// Import GSMTAP-over-pcap: walk every record, peel Ethernet/IPv4/UDP, decode the
/// GSMTAP header, and map the message body to the closest `AirEvent`.
fn import_gsmtap_pcap(bytes: &[u8]) -> Result<Import, ImportError> {
    let reader = pcap::Pcap::parse(bytes)?;
    let linktype = reader.linktype;

    // Gather (absolute ts_us, rat, dir, cell, payload) then rebase timestamps.
    struct Raw {
        ts_us: u64,
        rat: ocr_air::Rat,
        dir: ocr_air::Direction,
        cell: CellId,
        payload: ocr_air::Payload,
    }
    let mut raws: Vec<Raw> = Vec::new();
    let mut skips: Vec<SkipReason> = Vec::new();
    let mut records_total = 0usize;

    for rec in reader {
        // A structural pcap error (truncated / hostile length) aborts the import.
        let rec = rec?;
        records_total += 1;

        let Some(udp) = net::udp_payload(linktype, rec.data) else {
            skips.push(SkipReason::NotGsmtap);
            continue;
        };
        if udp.dst_port != gsmtap::GSMTAP_UDP_PORT && udp.src_port != gsmtap::GSMTAP_UDP_PORT {
            skips.push(SkipReason::NotGsmtap);
            continue;
        }
        let (hdr, body) = match gsmtap::GsmtapHdr::parse(udp.payload) {
            Ok(pair) => pair,
            Err(_) => {
                skips.push(SkipReason::BadGsmtapHeader);
                continue;
            }
        };
        match l3::map(&hdr, body) {
            Ok(mapped) => raws.push(Raw {
                ts_us: rec.ts_us,
                rat: mapped.rat,
                dir: mapped.dir,
                // GSMTAP has no engine cell id; group by ARFCN/EARFCN so the same
                // serving frequency is one opaque cell to the monitor.
                cell: CellId(hdr.arfcn() as u32),
                payload: mapped.payload,
            }),
            Err(reason) => skips.push(reason),
        }
    }

    // Rebase timestamps so the first mapped event sits at t=0 (pcap stores absolute
    // epoch times; the monitor only cares about relative spacing).
    let base = raws.iter().map(|r| r.ts_us).min().unwrap_or(0);
    let events: Vec<AirEvent> = raws
        .into_iter()
        .map(|r| AirEvent {
            t_us: r.ts_us - base,
            rat: r.rat,
            cell: r.cell,
            dir: r.dir,
            payload: r.payload,
        })
        .collect();

    let records_mapped = events.len();
    Ok(Import {
        format: Format::GsmtapPcap,
        events,
        records_total,
        records_mapped,
        skips,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ocr_air::{Payload, Rat};
    use ocr_gsm::{GsmMessage, IdentityType, A5};
    use ocr_lte::LteNasMessage;

    // ---- synthetic pcap builders (bytes written in-code, no binary fixture) ----

    /// Build a classic little-endian, microsecond pcap file wrapping each L3 body
    /// in Ethernet + IPv4 + UDP(->4729) + a GSMTAP v2 header.
    struct PcapBuilder {
        records: Vec<Vec<u8>>,
    }

    impl PcapBuilder {
        fn new() -> Self {
            Self {
                records: Vec::new(),
            }
        }

        /// Append one GSMTAP record: `gtype` is the GSMTAP payload type, `sub_type`
        /// the channel / NAS flag, `arfcn` the (uplink-flagged) frequency, `l3` the
        /// message body.
        fn push(&mut self, ts_us: u64, gtype: u8, sub_type: u8, arfcn: u16, l3: &[u8]) {
            // GSMTAP v2 header (16 bytes): version, hdr_len (4 words), type, slot.
            let mut g = vec![0x02u8, 0x04, gtype, 0x00];
            g.extend_from_slice(&arfcn.to_be_bytes());
            g.extend_from_slice(&[0u8, 0u8]); // signal_dbm, snr_db
            g.extend_from_slice(&0u32.to_be_bytes()); // frame number
            g.extend_from_slice(&[sub_type, 0x00, 0x00, 0x00]); // sub_type, antenna, slot, res
            g.extend_from_slice(l3);

            // UDP header (src 12345 -> dst 4729).
            let udp_len = (8 + g.len()) as u16;
            let mut udp = Vec::new();
            udp.extend_from_slice(&12345u16.to_be_bytes());
            udp.extend_from_slice(&4729u16.to_be_bytes());
            udp.extend_from_slice(&udp_len.to_be_bytes());
            udp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unchecked)
            udp.extend_from_slice(&g);

            // IPv4 header (20 bytes, protocol 17): version 4 / IHL 5, then DSCP/ECN.
            let total_len = (20 + udp.len()) as u16;
            let mut ip = vec![0x45u8, 0x00];
            ip.extend_from_slice(&total_len.to_be_bytes());
            ip.extend_from_slice(&0u16.to_be_bytes()); // id
            ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
            ip.push(64); // TTL
            ip.push(17); // protocol UDP
            ip.extend_from_slice(&0u16.to_be_bytes()); // checksum (unchecked)
            ip.extend_from_slice(&[10, 0, 0, 1]); // src
            ip.extend_from_slice(&[10, 0, 0, 2]); // dst
            ip.extend_from_slice(&udp);

            // Ethernet header (14 bytes, ethertype IPv4).
            let mut eth = Vec::new();
            eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // dst mac
            eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // src mac
            eth.extend_from_slice(&0x0800u16.to_be_bytes());
            eth.extend_from_slice(&ip);

            // Record header (little-endian, microsecond).
            let mut rec = Vec::new();
            let ts_sec = (ts_us / 1_000_000) as u32;
            let ts_usec = (ts_us % 1_000_000) as u32;
            rec.extend_from_slice(&ts_sec.to_le_bytes());
            rec.extend_from_slice(&ts_usec.to_le_bytes());
            rec.extend_from_slice(&(eth.len() as u32).to_le_bytes()); // incl_len
            rec.extend_from_slice(&(eth.len() as u32).to_le_bytes()); // orig_len
            rec.extend_from_slice(&eth);

            self.records.push(rec);
        }

        fn build(&self, linktype: u32) -> Vec<u8> {
            let mut out = Vec::new();
            // Global header: LE microsecond magic.
            out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
            out.extend_from_slice(&2u16.to_le_bytes()); // version major
            out.extend_from_slice(&4u16.to_le_bytes()); // version minor
            out.extend_from_slice(&0u32.to_le_bytes()); // thiszone
            out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
            out.extend_from_slice(&0xffffu32.to_le_bytes()); // snaplen
            out.extend_from_slice(&linktype.to_le_bytes());
            for r in &self.records {
                out.extend_from_slice(r);
            }
            out
        }
    }

    // GSM MM Identity Request (IMSI): PD=MM(0x05), MT=0x18, id type=IMSI(0x01).
    const GSM_IDENTITY_REQUEST_IMSI: &[u8] = &[0x05, 0x18, 0x01];
    // RR Ciphering Mode Command with SC=0 -> A5/0: PD=RR(0x06), MT=0x35, setting 0.
    const GSM_CIPHER_MODE_A5_0: &[u8] = &[0x06, 0x35, 0x00];
    // Plain EMM Identity Request: sec-hdr/PD octet 0x07, MT=0x55.
    const EMM_IDENTITY_REQUEST: &[u8] = &[0x07, 0x55];

    /// The required end-to-end proof (reader half): a synthetic GSMTAP-over-pcap
    /// capture, built byte for byte in-code, parses into exactly the `AirEvent`s the
    /// engine models — no binary blob shipped. The *monitor* half of the proof (that
    /// these events raise the expected findings) lives in `ocr-cli`, which owns the
    /// `ocr-detect` dependency; `ocr_cli::tests::synthetic_pcap_reaches_findings`.
    #[test]
    fn synthetic_pcap_maps_to_expected_events() {
        let mut b = PcapBuilder::new();
        // Two 2G Um records on the same ARFCN (871): a cleartext IMSI request and
        // a forced null cipher — both High-severity IMSI-catcher tells.
        b.push(
            1_000_000,
            gsmtap::GSMTAP_TYPE_UM,
            gsmtap::GSMTAP_CHANNEL_SDCCH,
            871,
            GSM_IDENTITY_REQUEST_IMSI,
        );
        b.push(
            1_000_100,
            gsmtap::GSMTAP_TYPE_UM,
            gsmtap::GSMTAP_CHANNEL_SDCCH,
            871,
            GSM_CIPHER_MODE_A5_0,
        );
        let file = b.build(net::LINKTYPE_ETHERNET);

        let import = import_bytes(&file).expect("synthetic pcap must import");
        assert_eq!(import.format, Format::GsmtapPcap);
        assert_eq!(import.records_total, 2);
        assert_eq!(import.records_mapped, 2);
        assert!(
            import.skips.is_empty(),
            "unexpected skips: {:?}",
            import.skips
        );

        // Timestamps rebased so the first event is at zero.
        assert_eq!(import.events[0].t_us, 0);
        assert_eq!(import.events[1].t_us, 100);
        // Both grouped under the ARFCN as the opaque cell id.
        assert_eq!(import.events[0].cell, CellId(871));

        assert_eq!(
            import.events[0].payload,
            Payload::Gsm(GsmMessage::IdentityRequest {
                id_type: IdentityType::Imsi
            })
        );
        assert_eq!(
            import.events[1].payload,
            Payload::Gsm(GsmMessage::CipherModeCommand {
                algorithm: A5::A5_0
            })
        );
    }

    /// The LTE NAS path: a plain EMM Identity Request over GSMTAP maps to the
    /// engine's `IdentityRequest`, with direction taken from the uplink flag.
    #[test]
    fn synthetic_pcap_lte_nas_identity_request() {
        let mut b = PcapBuilder::new();
        b.push(
            5,
            gsmtap::GSMTAP_TYPE_LTE_NAS,
            gsmtap::GSMTAP_LTE_NAS_PLAIN,
            0x4000 | 1200, // EARFCN 1200, uplink flag set -> UE->NET
            EMM_IDENTITY_REQUEST,
        );
        let import = import_bytes(&b.build(net::LINKTYPE_ETHERNET)).expect("import");
        assert_eq!(import.records_mapped, 1);
        assert_eq!(import.events[0].rat, Rat::Lte);
        assert_eq!(import.events[0].dir, ocr_air::Direction::UeToNet);
        assert_eq!(
            import.events[0].payload,
            Payload::LteNas(LteNasMessage::IdentityRequest)
        );
    }

    /// A capture that mixes GSMTAP with unrelated traffic and an undecodable
    /// generation: mapped records are kept, the rest are counted as skips.
    #[test]
    fn non_gsmtap_and_undecoded_records_are_skipped_not_fatal() {
        let mut b = PcapBuilder::new();
        b.push(
            0,
            gsmtap::GSMTAP_TYPE_UM,
            gsmtap::GSMTAP_CHANNEL_SDCCH,
            10,
            GSM_IDENTITY_REQUEST_IMSI,
        );
        // LTE RRC: recognised generation, ASN.1 body not decoded -> skip.
        b.push(
            1,
            gsmtap::GSMTAP_TYPE_LTE_RRC,
            0,
            100,
            &[0xde, 0xad, 0xbe, 0xef],
        );
        let import = import_bytes(&b.build(net::LINKTYPE_ETHERNET)).expect("import");
        assert_eq!(import.records_total, 2);
        assert_eq!(import.records_mapped, 1);
        assert_eq!(import.records_skipped(), 1);
        assert!(matches!(
            import.skips[0],
            SkipReason::RecognisedButUndecoded { .. }
        ));
    }

    #[test]
    fn detect_format_distinguishes_pcap_from_ndjson() {
        let mut b = PcapBuilder::new();
        b.push(
            0,
            gsmtap::GSMTAP_TYPE_UM,
            gsmtap::GSMTAP_CHANNEL_SDCCH,
            1,
            GSM_IDENTITY_REQUEST_IMSI,
        );
        assert_eq!(
            detect_format(&b.build(net::LINKTYPE_ETHERNET)),
            Format::GsmtapPcap
        );

        assert_eq!(detect_format(b"{\"t_us\":0}\n"), Format::Ndjson);
        assert_eq!(detect_format(b""), Format::Ndjson);
        assert_eq!(detect_format(&[0x00, 0x01, 0x02]), Format::Ndjson);
    }

    /// Round-trip the native NDJSON format through the importer.
    #[test]
    fn ndjson_import_round_trips() {
        let ev = AirEvent {
            t_us: 7,
            rat: Rat::Lte,
            cell: CellId(3),
            dir: ocr_air::Direction::NetToUe,
            payload: Payload::LteNas(LteNasMessage::AttachReject { cause: 15 }),
        };
        let mut buf = Vec::new();
        ndjson::write_events(std::slice::from_ref(&ev), &mut buf).unwrap();

        let import = import_bytes(&buf).expect("ndjson import");
        assert_eq!(import.format, Format::Ndjson);
        assert_eq!(import.records_total, 1);
        assert_eq!(import.events, vec![ev]);
    }

    /// Totality: truncating a valid pcap at every possible length must never panic
    /// — the parser stays total, returning `Ok` or `Err` for each prefix.
    #[test]
    fn truncations_never_panic() {
        let mut b = PcapBuilder::new();
        b.push(
            0,
            gsmtap::GSMTAP_TYPE_UM,
            gsmtap::GSMTAP_CHANNEL_SDCCH,
            5,
            GSM_IDENTITY_REQUEST_IMSI,
        );
        b.push(
            1,
            gsmtap::GSMTAP_TYPE_LTE_NAS,
            gsmtap::GSMTAP_LTE_NAS_PLAIN,
            5,
            EMM_IDENTITY_REQUEST,
        );
        let file = b.build(net::LINKTYPE_ETHERNET);
        for n in 0..=file.len() {
            let _ = import_bytes(&file[..n]);
        }
    }

    /// Totality under corruption: flipping bytes across the file never panics.
    #[test]
    fn corruption_never_panics() {
        let mut b = PcapBuilder::new();
        b.push(
            0,
            gsmtap::GSMTAP_TYPE_UM,
            gsmtap::GSMTAP_CHANNEL_SDCCH,
            5,
            GSM_IDENTITY_REQUEST_IMSI,
        );
        let base = b.build(net::LINKTYPE_ETHERNET);
        for i in 0..base.len() {
            let mut f = base.clone();
            f[i] ^= 0xff;
            let _ = import_bytes(&f);
        }
    }
}
