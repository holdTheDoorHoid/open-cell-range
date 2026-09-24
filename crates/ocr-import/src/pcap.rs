//! A minimal reader for the classic pcap file format (the libpcap "savefile"
//! header, not the newer pcapng block format).
//!
//! Only what an importer needs: the global header (to learn byte order, timestamp
//! precision, and the link-layer type), then each record's header + captured
//! bytes. The record payload is handed on to [`crate::net`] to peel Ethernet /
//! IPv4 / UDP, and to [`crate::gsmtap`] for the GSMTAP header itself.
//!
//! Robustness: this parser is total. Every read is bounds-checked; a structurally
//! broken file (bad magic, a truncated header, a record length that runs past the
//! end of the buffer) yields an [`Err`], never a panic. This is deliberate — the
//! parser is intended to be fuzzed.

use core::fmt;

/// The four classic-pcap magic numbers, as they appear as the first four bytes on
/// disk. Two byte orders, each in microsecond- and nanosecond-timestamp form.
const MAGIC_BE_US: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
const MAGIC_LE_US: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
const MAGIC_BE_NS: [u8; 4] = [0xa1, 0xb2, 0x3c, 0x4d];
const MAGIC_LE_NS: [u8; 4] = [0x4d, 0x3c, 0xb2, 0xa1];

/// Size of the classic-pcap global (file) header, in bytes.
const GLOBAL_HEADER_LEN: usize = 24;
/// Size of a per-record header, in bytes.
const RECORD_HEADER_LEN: usize = 16;

/// Byte order the writer used, learned from the magic number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

/// A pcap parse failure. Structural only — a *packet* that simply isn't GSMTAP is
/// not an error here (the importer skips it); these are file-level problems.
#[derive(Debug, PartialEq, Eq)]
pub enum PcapError {
    /// Fewer than [`GLOBAL_HEADER_LEN`] bytes, or the global header is cut short.
    ShortGlobalHeader,
    /// The first four bytes are not a recognised classic-pcap magic number.
    BadMagic([u8; 4]),
    /// A record header, or a record's captured bytes, run past the buffer end.
    TruncatedRecord {
        /// Byte offset in the file where the truncation was detected.
        offset: usize,
    },
    /// A record's `incl_len` is implausibly large (guards a hostile length field).
    RecordTooLong { offset: usize, incl_len: u32 },
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapError::ShortGlobalHeader => {
                write!(f, "pcap: file is shorter than the 24-byte global header")
            }
            PcapError::BadMagic(m) => write!(
                f,
                "pcap: unrecognised magic {:02x}{:02x}{:02x}{:02x} (not a classic .pcap)",
                m[0], m[1], m[2], m[3]
            ),
            PcapError::TruncatedRecord { offset } => {
                write!(f, "pcap: record truncated at byte offset {offset}")
            }
            PcapError::RecordTooLong { offset, incl_len } => write!(
                f,
                "pcap: record at offset {offset} claims {incl_len} captured bytes, \
                 which exceeds the rest of the file"
            ),
        }
    }
}

impl std::error::Error for PcapError {}

/// One record (captured packet) as it sits in the file.
#[derive(Debug, Clone, Copy)]
pub struct Record<'a> {
    /// Timestamp in microseconds since the Unix epoch (nanosecond files are
    /// divided down to microseconds).
    pub ts_us: u64,
    /// Number of captured bytes actually present in the file for this record.
    pub incl_len: u32,
    /// Original on-wire length (may exceed `incl_len` when the capture was snapped).
    pub orig_len: u32,
    /// The captured bytes: a link-layer frame whose type is [`Pcap::linktype`].
    pub data: &'a [u8],
}

/// A parsed classic-pcap file. Construct with [`Pcap::parse`], then iterate to walk
/// the records. The struct itself is the iterator (it owns the read cursor).
#[derive(Debug, Clone)]
pub struct Pcap<'a> {
    /// The link-layer header type (DLT / LINKTYPE_*) declared by the global header.
    pub linktype: u32,
    /// Whether record timestamps were written in nanoseconds (already normalised
    /// to microseconds in [`Record::ts_us`]; kept for reporting).
    pub nanos: bool,
    /// The byte order the file was written in.
    pub endian: Endian,
    data: &'a [u8],
    off: usize,
}

fn rd_u32(buf: &[u8], off: usize, e: Endian) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    let arr = [b[0], b[1], b[2], b[3]];
    Some(match e {
        Endian::Big => u32::from_be_bytes(arr),
        Endian::Little => u32::from_le_bytes(arr),
    })
}

impl<'a> Pcap<'a> {
    /// Parse the global header and position the cursor at the first record.
    pub fn parse(data: &'a [u8]) -> Result<Self, PcapError> {
        let head = data
            .get(0..GLOBAL_HEADER_LEN)
            .ok_or(PcapError::ShortGlobalHeader)?;
        let magic = [head[0], head[1], head[2], head[3]];
        let (endian, nanos) = match magic {
            MAGIC_BE_US => (Endian::Big, false),
            MAGIC_LE_US => (Endian::Little, false),
            MAGIC_BE_NS => (Endian::Big, true),
            MAGIC_LE_NS => (Endian::Little, true),
            other => return Err(PcapError::BadMagic(other)),
        };
        // Bytes 4..20 are version/zone/sigfigs/snaplen — not needed for import.
        // The link-layer type is the last u32 of the 24-byte header.
        let linktype = rd_u32(head, 20, endian).ok_or(PcapError::ShortGlobalHeader)?;
        Ok(Pcap {
            linktype,
            nanos,
            endian,
            data,
            off: GLOBAL_HEADER_LEN,
        })
    }
}

impl<'a> Iterator for Pcap<'a> {
    type Item = Result<Record<'a>, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Clean end of file: cursor exactly at the end.
        if self.off >= self.data.len() {
            return None;
        }
        let hdr_start = self.off;
        // A record header must fit.
        let hdr = match self.data.get(hdr_start..hdr_start + RECORD_HEADER_LEN) {
            Some(h) => h,
            None => return Some(Err(PcapError::TruncatedRecord { offset: hdr_start })),
        };
        // These reads cannot fail (hdr is exactly 16 bytes) but stay total anyway.
        let ts_sec = rd_u32(hdr, 0, self.endian)? as u64;
        let ts_frac = rd_u32(hdr, 4, self.endian)? as u64;
        let incl_len = rd_u32(hdr, 8, self.endian)?;
        let orig_len = rd_u32(hdr, 12, self.endian)?;

        let sub_us = if self.nanos { ts_frac / 1_000 } else { ts_frac };
        let ts_us = ts_sec.saturating_mul(1_000_000).saturating_add(sub_us);

        let data_start = hdr_start + RECORD_HEADER_LEN;
        let want = incl_len as usize;
        let data = match self.data.get(data_start..data_start + want) {
            Some(d) => d,
            None => {
                // Distinguish "hostile huge length" from "file ends mid-record".
                let remaining = self.data.len().saturating_sub(data_start);
                if want > remaining {
                    return Some(Err(PcapError::RecordTooLong {
                        offset: hdr_start,
                        incl_len,
                    }));
                }
                return Some(Err(PcapError::TruncatedRecord { offset: data_start }));
            }
        };
        self.off = data_start + want;
        Some(Ok(Record {
            ts_us,
            incl_len,
            orig_len,
            data,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a one-record pcap with the given magic bytes and record payload.
    fn one_record(
        magic: [u8; 4],
        endian: Endian,
        ts_sec: u32,
        ts_frac: u32,
        body: &[u8],
    ) -> Vec<u8> {
        let wr16 = |v: u16| match endian {
            Endian::Big => v.to_be_bytes(),
            Endian::Little => v.to_le_bytes(),
        };
        let wr32 = |v: u32| match endian {
            Endian::Big => v.to_be_bytes(),
            Endian::Little => v.to_le_bytes(),
        };
        let mut out = Vec::new();
        out.extend_from_slice(&magic);
        out.extend_from_slice(&wr16(2));
        out.extend_from_slice(&wr16(4));
        out.extend_from_slice(&wr32(0));
        out.extend_from_slice(&wr32(0));
        out.extend_from_slice(&wr32(0xffff));
        out.extend_from_slice(&wr32(1)); // linktype ethernet
        out.extend_from_slice(&wr32(ts_sec));
        out.extend_from_slice(&wr32(ts_frac));
        out.extend_from_slice(&wr32(body.len() as u32));
        out.extend_from_slice(&wr32(body.len() as u32));
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn parses_little_endian_microsecond() {
        let f = one_record(MAGIC_LE_US, Endian::Little, 3, 250_000, b"hello");
        let mut p = Pcap::parse(&f).expect("parse");
        assert_eq!(p.endian, Endian::Little);
        assert!(!p.nanos);
        assert_eq!(p.linktype, 1);
        let rec = p.next().unwrap().unwrap();
        assert_eq!(rec.ts_us, 3_250_000);
        assert_eq!(rec.data, b"hello");
        assert!(p.next().is_none());
    }

    #[test]
    fn parses_big_endian_nanosecond_scaled_to_us() {
        // 500_000 ns -> 500 us.
        let f = one_record(MAGIC_BE_NS, Endian::Big, 1, 500_000, b"x");
        let mut p = Pcap::parse(&f).expect("parse");
        assert_eq!(p.endian, Endian::Big);
        assert!(p.nanos);
        let rec = p.next().unwrap().unwrap();
        assert_eq!(rec.ts_us, 1_000_500);
    }

    #[test]
    fn rejects_bad_magic() {
        let f = [0u8; 24];
        assert!(matches!(Pcap::parse(&f), Err(PcapError::BadMagic(_))));
    }

    #[test]
    fn rejects_short_global_header() {
        assert!(matches!(
            Pcap::parse(&[0xd4, 0xc3]),
            Err(PcapError::ShortGlobalHeader)
        ));
    }

    #[test]
    fn hostile_record_length_is_error_not_panic() {
        let mut f = one_record(MAGIC_LE_US, Endian::Little, 0, 0, b"ok");
        // Overwrite the record's incl_len (offset 24+8=32) with a huge value.
        f[32..36].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        let mut p = Pcap::parse(&f).unwrap();
        assert!(matches!(
            p.next(),
            Some(Err(PcapError::RecordTooLong { .. }))
        ));
    }

    #[test]
    fn truncated_record_header_is_error() {
        let mut f = one_record(MAGIC_LE_US, Endian::Little, 0, 0, b"ok");
        f.truncate(24 + 8); // half a record header
        let mut p = Pcap::parse(&f).unwrap();
        assert!(matches!(
            p.next(),
            Some(Err(PcapError::TruncatedRecord { .. }))
        ));
    }
}
