//! Parser-robustness and serialization-determinism tests for `ocr-import`.
//!
//! The crate documents every parser as **total**: all reads bounds-checked, and
//! malformed input yields `Err` (or a `SkipReason`), never a panic (see the
//! `# Robustness` section of `lib.rs`). These tests hold that contract to a large
//! volume of hostile input — pseudo-random byte streams and mutated copies of a
//! valid GSMTAP-over-pcap fixture — driven through the pcap reader and the NDJSON
//! reader. A panic anywhere fails the test loudly.
//!
//! All randomness is a hand-rolled **splitmix64** seeded with a fixed constant, so
//! the corpus is byte-for-byte identical on every run and on every machine. No
//! `rand`/`getrandom` or any other dependency is added — this matches the project's
//! determinism discipline (`DESIGN.md` section 3: no OS entropy).

use ocr_air::{AirEvent, CellId, Direction, Payload, Rat};
use ocr_gsm::{GsmMessage, IdentityType, A5};
use ocr_identity::Plmn;
use ocr_import::{detect_format, import_bytes, ndjson, pcap, Format};
use ocr_lte::LteNasMessage;
use ocr_nr::{NrNasMessage, NrRrcMessage};

// ---------------------------------------------------------------------------
// Deterministic PRNG (splitmix64), seeded with a fixed constant.
// ---------------------------------------------------------------------------

/// A minimal splitmix64 generator. Deterministic, no dependency, no OS entropy.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seed with a fixed constant at the call site — never OS entropy.
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A byte.
    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    /// A value in `0..n` (n must be non-zero).
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    /// A fresh buffer of `len` random bytes.
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        for b in v.iter_mut() {
            *b = self.next_u8();
        }
        v
    }
}

/// The fixed seed for the whole corpus. Change it and the corpus changes wholesale,
/// but any single run is fully reproducible.
const CORPUS_SEED: u64 = 0xC0FF_EE15_0CE1_1A2B;

/// How many pseudo-random / mutated inputs to generate per fuzz loop.
const FUZZ_ITERS: usize = 10_000;

// ---------------------------------------------------------------------------
// A byte-accurate GSMTAP-over-pcap fixture builder (public API + public consts
// only; mirrors the header layout the crate documents and parses).
// ---------------------------------------------------------------------------

struct PcapBuilder {
    records: Vec<Vec<u8>>,
}

impl PcapBuilder {
    fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Append one GSMTAP record wrapped in Ethernet + IPv4 + UDP(->4729).
    fn push(&mut self, ts_us: u64, gtype: u8, sub_type: u8, arfcn: u16, l3: &[u8]) {
        // GSMTAP v2 header: version, hdr_len (4 words), type, timeslot.
        let mut g = vec![0x02u8, 0x04, gtype, 0x00];
        g.extend_from_slice(&arfcn.to_be_bytes());
        g.extend_from_slice(&[0u8, 0u8]); // signal_dbm, snr_db
        g.extend_from_slice(&0u32.to_be_bytes()); // frame number
        g.extend_from_slice(&[sub_type, 0u8, 0u8, 0u8]); // sub_type, antenna, slot, res
        g.extend_from_slice(l3);

        // UDP header (src 12345 -> dst 4729).
        let udp_len = (8 + g.len()) as u16;
        let mut udp = Vec::new();
        udp.extend_from_slice(&12345u16.to_be_bytes());
        udp.extend_from_slice(&4729u16.to_be_bytes());
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unchecked)
        udp.extend_from_slice(&g);

        // IPv4 header (protocol 17).
        let total_len = (20 + udp.len()) as u16;
        let mut ip = vec![0x45u8, 0x00];
        ip.extend_from_slice(&total_len.to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.push(64);
        ip.push(17);
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&udp);

        // Ethernet header (ethertype IPv4).
        let mut eth = Vec::new();
        eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        eth.extend_from_slice(&0x0800u16.to_be_bytes());
        eth.extend_from_slice(&ip);

        // Record header (little-endian, microsecond).
        let mut rec = Vec::new();
        let ts_sec = (ts_us / 1_000_000) as u32;
        let ts_usec = (ts_us % 1_000_000) as u32;
        rec.extend_from_slice(&ts_sec.to_le_bytes());
        rec.extend_from_slice(&ts_usec.to_le_bytes());
        rec.extend_from_slice(&(eth.len() as u32).to_le_bytes());
        rec.extend_from_slice(&(eth.len() as u32).to_le_bytes());
        rec.extend_from_slice(&eth);

        self.records.push(rec);
    }

    /// Also append a non-GSMTAP UDP record (different dst port) so the "skip"
    /// path is inside the fixture too.
    fn push_non_gsmtap(&mut self, ts_us: u64) {
        // Reuse push() shape but on a non-4729 port by hand-rolling a tiny frame.
        let mut udp = Vec::new();
        udp.extend_from_slice(&1000u16.to_be_bytes());
        udp.extend_from_slice(&1001u16.to_be_bytes()); // not 4729
        udp.extend_from_slice(&(8u16 + 4).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        let total_len = (20 + udp.len()) as u16;
        let mut ip = vec![0x45u8, 0x00];
        ip.extend_from_slice(&total_len.to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.push(64);
        ip.push(17);
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&udp);

        let mut eth = Vec::new();
        eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        eth.extend_from_slice(&0x0800u16.to_be_bytes());
        eth.extend_from_slice(&ip);

        let mut rec = Vec::new();
        let ts_sec = (ts_us / 1_000_000) as u32;
        let ts_usec = (ts_us % 1_000_000) as u32;
        rec.extend_from_slice(&ts_sec.to_le_bytes());
        rec.extend_from_slice(&ts_usec.to_le_bytes());
        rec.extend_from_slice(&(eth.len() as u32).to_le_bytes());
        rec.extend_from_slice(&(eth.len() as u32).to_le_bytes());
        rec.extend_from_slice(&eth);
        self.records.push(rec);
    }

    fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Global header: LE microsecond magic, linktype ethernet (1).
        out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0xffffu32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
        for r in &self.records {
            out.extend_from_slice(r);
        }
        out
    }
}

// GSMTAP payload/channel constants that build valid records.
const GSMTAP_TYPE_UM: u8 = 0x01;
const GSMTAP_TYPE_LTE_NAS: u8 = 0x12;
const GSMTAP_TYPE_LTE_RRC: u8 = 0x0d;
const GSMTAP_CHANNEL_SDCCH: u8 = 0x06;
const GSMTAP_LTE_NAS_PLAIN: u8 = 0x00;

// L3 message bodies.
const GSM_IDENTITY_REQUEST_IMSI: &[u8] = &[0x05, 0x18, 0x01];
const GSM_CIPHER_MODE_A5_0: &[u8] = &[0x06, 0x35, 0x00];
const EMM_IDENTITY_REQUEST: &[u8] = &[0x07, 0x55];

/// A valid, mapping, multi-record GSMTAP pcap fixture: two 2G Um records, one
/// LTE NAS record, one non-GSMTAP record, and one recognised-but-undecoded LTE
/// RRC record. It exercises the map path, the skip path, and the not-GSMTAP path
/// all in one file, so mutating it reaches every branch.
fn valid_pcap_fixture() -> Vec<u8> {
    let mut b = PcapBuilder::new();
    b.push(
        1_000_000,
        GSMTAP_TYPE_UM,
        GSMTAP_CHANNEL_SDCCH,
        871,
        GSM_IDENTITY_REQUEST_IMSI,
    );
    b.push(
        1_000_100,
        GSMTAP_TYPE_UM,
        GSMTAP_CHANNEL_SDCCH,
        871,
        GSM_CIPHER_MODE_A5_0,
    );
    b.push(
        2_000_000,
        GSMTAP_TYPE_LTE_NAS,
        GSMTAP_LTE_NAS_PLAIN,
        0x4000 | 1200, // uplink flag set
        EMM_IDENTITY_REQUEST,
    );
    b.push_non_gsmtap(2_500_000);
    b.push(
        3_000_000,
        GSMTAP_TYPE_LTE_RRC,
        0,
        100,
        &[0xde, 0xad, 0xbe, 0xef], // recognised RAT, undecoded ASN.1 body
    );
    b.build()
}

// ---------------------------------------------------------------------------
// Drivers: every entry point a byte buffer can reach. Each is TOTAL — it must
// return, never panic, for any input. The helpers deliberately consume the
// `Result` (matching both arms) to make "returns a Result" explicit.
// ---------------------------------------------------------------------------

/// Drive the whole importer plus the pcap reader directly (parse + full iteration
/// of every record). Returns without panicking for any input, or the test fails.
fn drive_pcap_path(bytes: &[u8]) {
    // Top-level importer (auto-detects format).
    match import_bytes(bytes) {
        Ok(import) => {
            // Touch the fields so a bad Import can't be optimised away.
            assert_eq!(import.records_mapped, import.events.len());
            let _ = import.records_skipped();
            let _ = import.format;
        }
        Err(_) => { /* a structural error is a valid, non-panicking outcome */ }
    }
    // Format sniffing must be total too.
    let _ = detect_format(bytes);
    // The pcap reader on its own: parse, then walk every record to the end.
    if let Ok(reader) = pcap::Pcap::parse(bytes) {
        let _lt = reader.linktype;
        for rec in reader {
            match rec {
                Ok(r) => {
                    let _ = (r.ts_us, r.incl_len, r.orig_len, r.data.len());
                }
                Err(_) => break, // a structural record error ends iteration
            }
        }
    }
}

/// Drive the NDJSON reader over a whole buffer, plus line-by-line `from_line`.
fn drive_ndjson_path(bytes: &[u8]) {
    // Whole-stream reader. `&[u8]` is a `BufRead`.
    match ndjson::read_events(bytes) {
        Ok(events) => {
            let _ = events.len();
        }
        Err(_) => { /* malformed NDJSON is a valid, non-panicking outcome */ }
    }
    // Also the top-level importer, which routes non-pcap buffers to NDJSON.
    let _ = import_bytes(bytes);
    // Line-level parser over any UTF-8 sub-slices we can carve out.
    if let Ok(text) = core::str::from_utf8(bytes) {
        for line in text.lines() {
            let _ = ndjson::from_line(line);
        }
    }
}

// ---------------------------------------------------------------------------
// 1. Pseudo-random byte streams.
// ---------------------------------------------------------------------------

/// `FUZZ_ITERS` fully random byte streams through both readers: no panic, ever.
#[test]
fn random_bytes_never_panic() {
    let mut rng = SplitMix64::new(CORPUS_SEED);
    for _ in 0..FUZZ_ITERS {
        let len = rng.below(1025); // 0..=1024
        let buf = rng.bytes(len);
        drive_pcap_path(&buf);
        drive_ndjson_path(&buf);
    }
}

/// Random byte streams that are forced to *start* with a valid classic-pcap magic,
/// so the corpus reaches deep into the record iterator rather than bouncing off
/// `BadMagic` immediately. Covers hostile length fields the RNG happens to produce.
#[test]
fn random_bytes_with_pcap_magic_never_panic() {
    // All four classic-pcap magics, so both byte orders and both timestamp scales
    // are exercised.
    const MAGICS: [[u8; 4]; 4] = [
        [0xa1, 0xb2, 0xc3, 0xd4],
        [0xd4, 0xc3, 0xb2, 0xa1],
        [0xa1, 0xb2, 0x3c, 0x4d],
        [0x4d, 0x3c, 0xb2, 0xa1],
    ];
    let mut rng = SplitMix64::new(CORPUS_SEED ^ 0xA5A5_A5A5_A5A5_A5A5);
    for _ in 0..FUZZ_ITERS {
        let len = rng.below(513); // 0..=512
        let mut buf = rng.bytes(len);
        let magic = MAGICS[rng.below(MAGICS.len())];
        // Prepend the magic (buffer may be shorter than a full global header).
        let mut with_magic = Vec::with_capacity(4 + buf.len());
        with_magic.extend_from_slice(&magic);
        with_magic.append(&mut buf);
        drive_pcap_path(&with_magic);
    }
}

// ---------------------------------------------------------------------------
// 2. Mutated copies of a valid GSMTAP pcap fixture.
// ---------------------------------------------------------------------------

/// Truncation at every offset (0..=len): a prefix of a valid pcap must parse to
/// `Ok`/`Err` at every cut, never panic.
#[test]
fn pcap_truncation_at_every_offset_never_panics() {
    let file = valid_pcap_fixture();
    // The full file must genuinely import first — a real fixture, not noise.
    let full = import_bytes(&file).expect("the fixture must be a valid, importable pcap");
    assert_eq!(full.format, Format::GsmtapPcap);
    assert!(
        full.records_mapped >= 3,
        "fixture should map its GSMTAP records"
    );

    for n in 0..=file.len() {
        drive_pcap_path(&file[..n]);
    }
}

/// Single-byte corruption: flip each byte in turn (three masks) and re-parse.
#[test]
fn pcap_single_byte_flips_never_panic() {
    let file = valid_pcap_fixture();
    for (i, _) in file.iter().enumerate() {
        for mask in [0x01u8, 0x80, 0xff] {
            let mut f = file.clone();
            f[i] ^= mask;
            drive_pcap_path(&f);
        }
    }
}

/// Oversized length fields: stamp huge u32 values across 4-byte-aligned windows of
/// a valid pcap (this hits record `incl_len`, IP/UDP length fields, etc.) and
/// confirm the guarded length handling never panics or allocates unboundedly.
#[test]
fn pcap_oversized_length_fields_never_panic() {
    let file = valid_pcap_fixture();
    for start in (0..file.len().saturating_sub(4)).step_by(1) {
        for big in [0xffff_ffffu32, 0x7fff_ffff, 0x8000_0000, 0x0010_0000] {
            let mut f = file.clone();
            f[start..start + 4].copy_from_slice(&big.to_le_bytes());
            drive_pcap_path(&f);
        }
    }
}

/// PRNG-driven multi-byte mutation of the valid fixture: 1..=8 random positions set
/// to random bytes, `FUZZ_ITERS` times.
#[test]
fn pcap_prng_mutations_never_panic() {
    let file = valid_pcap_fixture();
    let mut rng = SplitMix64::new(CORPUS_SEED ^ 0x1234_5678_9ABC_DEF0);
    for _ in 0..FUZZ_ITERS {
        let mut f = file.clone();
        // Optionally truncate to a random length first.
        if rng.below(4) == 0 && !f.is_empty() {
            let keep = rng.below(f.len() + 1);
            f.truncate(keep);
        }
        if !f.is_empty() {
            let muts = 1 + rng.below(8);
            for _ in 0..muts {
                let pos = rng.below(f.len());
                f[pos] = rng.next_u8();
            }
        }
        drive_pcap_path(&f);
    }
}

// ---------------------------------------------------------------------------
// 3. Mutated copies of a valid NDJSON capture.
// ---------------------------------------------------------------------------

/// A diverse, hand-built event set covering every `Payload` arm plus fixed-array
/// crypto fields (RAND/AUTN) and variable-length byte fields (res*), so mutation
/// and round-trip exercise the serialization edges.
fn diverse_events() -> Vec<AirEvent> {
    vec![
        AirEvent {
            t_us: 0,
            rat: Rat::Gsm,
            cell: CellId(871),
            dir: Direction::NetToUe,
            payload: Payload::Gsm(GsmMessage::IdentityRequest {
                id_type: IdentityType::Imsi,
            }),
        },
        AirEvent {
            t_us: 100,
            rat: Rat::Gsm,
            cell: CellId(871),
            dir: Direction::NetToUe,
            payload: Payload::Gsm(GsmMessage::CipherModeCommand {
                algorithm: A5::A5_0,
            }),
        },
        AirEvent {
            t_us: 250,
            rat: Rat::Gsm,
            cell: CellId(12),
            dir: Direction::NetToUe,
            payload: Payload::Gsm(GsmMessage::SystemInformation {
                plmn: Plmn::new(310, 260, 3),
                lac: 4660,
                cell_id: 7,
            }),
        },
        AirEvent {
            t_us: 400,
            rat: Rat::Gsm,
            cell: CellId(12),
            dir: Direction::NetToUe,
            payload: Payload::Gsm(GsmMessage::AuthenticationRequest {
                rand: [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
            }),
        },
        AirEvent {
            t_us: 500,
            rat: Rat::Lte,
            cell: CellId(1200),
            dir: Direction::NetToUe,
            payload: Payload::LteNas(LteNasMessage::AttachReject { cause: 15 }),
        },
        AirEvent {
            t_us: 600,
            rat: Rat::Lte,
            cell: CellId(1200),
            dir: Direction::UeToNet,
            payload: Payload::LteNas(LteNasMessage::IdentityRequest),
        },
        AirEvent {
            t_us: 700,
            rat: Rat::Nr,
            cell: CellId(3),
            dir: Direction::NetToUe,
            payload: Payload::NrNas(NrNasMessage::AuthenticationRequest {
                rand: [0xa5; 16],
                autn: [0x5a; 16],
            }),
        },
        AirEvent {
            t_us: 800,
            rat: Rat::Nr,
            cell: CellId(3),
            dir: Direction::UeToNet,
            payload: Payload::NrNas(NrNasMessage::AuthenticationResponse {
                res_star: vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02],
            }),
        },
        AirEvent {
            t_us: 900,
            rat: Rat::Nr,
            cell: CellId(3),
            dir: Direction::NetToUe,
            payload: Payload::NrRrc(NrRrcMessage::SystemInformation {
                plmn: Plmn::new(1, 1, 2),
                tac: 1,
                cell_id: 42,
                allows_downgrade: true,
            }),
        },
    ]
}

fn valid_ndjson_fixture() -> Vec<u8> {
    let mut buf = Vec::new();
    ndjson::write_events(&diverse_events(), &mut buf).expect("write_events must succeed");
    buf
}

/// Truncation at every offset of a valid NDJSON capture: no panic.
#[test]
fn ndjson_truncation_at_every_offset_never_panics() {
    let file = valid_ndjson_fixture();
    // Sanity: the fixture reads back to the exact events first.
    let parsed = ndjson::read_events(&file[..]).expect("fixture must parse");
    assert_eq!(parsed, diverse_events());

    for n in 0..=file.len() {
        drive_ndjson_path(&file[..n]);
    }
}

/// Single-byte corruption of a valid NDJSON capture (three masks each): no panic.
/// Byte flips routinely produce invalid UTF-8 and invalid JSON; both must be `Err`.
#[test]
fn ndjson_single_byte_flips_never_panic() {
    let file = valid_ndjson_fixture();
    for (i, _) in file.iter().enumerate() {
        for mask in [0x01u8, 0x20, 0xff] {
            let mut f = file.clone();
            f[i] ^= mask;
            drive_ndjson_path(&f);
        }
    }
}

/// PRNG-driven multi-byte mutation of the valid NDJSON fixture, `FUZZ_ITERS` times,
/// including random truncation and random byte injection.
#[test]
fn ndjson_prng_mutations_never_panic() {
    let file = valid_ndjson_fixture();
    let mut rng = SplitMix64::new(CORPUS_SEED ^ 0x0F0F_0F0F_F0F0_F0F0);
    for _ in 0..FUZZ_ITERS {
        let mut f = file.clone();
        if rng.below(4) == 0 && !f.is_empty() {
            let keep = rng.below(f.len() + 1);
            f.truncate(keep);
        }
        if !f.is_empty() {
            let muts = 1 + rng.below(8);
            for _ in 0..muts {
                let pos = rng.below(f.len());
                f[pos] = rng.next_u8();
            }
        }
        // Occasionally inject a random newline to reshape the line structure.
        if rng.below(3) == 0 {
            f.push(b'\n');
            let extra_len = rng.below(64);
            let mut extra = rng.bytes(extra_len);
            f.append(&mut extra);
        }
        drive_ndjson_path(&f);
    }
}

// ---------------------------------------------------------------------------
// 4. Empty and degenerate inputs (explicit, named cases).
// ---------------------------------------------------------------------------

/// Empty input across every entry point: a Result, never a panic. Empty is NDJSON
/// by the documented default and yields zero events.
#[test]
fn empty_input_is_handled_everywhere() {
    let empty: &[u8] = &[];

    let import = import_bytes(empty).expect("empty input imports as empty NDJSON");
    assert_eq!(import.format, Format::Ndjson);
    assert!(import.events.is_empty());
    assert_eq!(import.records_total, 0);

    assert_eq!(detect_format(empty), Format::Ndjson);

    let events = ndjson::read_events(empty).expect("empty NDJSON is zero events");
    assert!(events.is_empty());

    // A pcap parse on empty is a structural error (too short), not a panic.
    assert!(pcap::Pcap::parse(empty).is_err());

    // `from_line` on empty/blank input is an error, not a panic.
    assert!(ndjson::from_line("").is_err());
    assert!(ndjson::from_line("   ").is_err());
    assert!(ndjson::from_line("not json").is_err());
}

// ---------------------------------------------------------------------------
// 5. NDJSON serialization determinism + round-trip (value added at the shared
//    reader layer; the scenario-level record/replay proof lives in ocr-cli).
// ---------------------------------------------------------------------------

/// Serializing the same events must produce byte-identical NDJSON every time, and
/// the buffer must round-trip losslessly and idempotently. This guards the
/// reproducibility guarantee at the on-disk boundary: a capture written on any
/// machine is the same bytes, and replays identically.
#[test]
fn ndjson_serialization_is_deterministic_and_round_trips() {
    let events = diverse_events();

    // Write determinism: two independent serializations are byte-identical.
    let mut a = Vec::new();
    let mut b = Vec::new();
    ndjson::write_events(&events, &mut a).unwrap();
    ndjson::write_events(&events, &mut b).unwrap();
    assert_eq!(a, b, "NDJSON serialization must be byte-deterministic");

    // Round-trip: read back to the exact events.
    let parsed = ndjson::read_events(&a[..]).unwrap();
    assert_eq!(parsed, events, "NDJSON must round-trip losslessly");

    // Idempotent: writing the re-read events reproduces the same bytes.
    let mut c = Vec::new();
    ndjson::write_events(&parsed, &mut c).unwrap();
    assert_eq!(a, c, "write(read(write(x))) must equal write(x)");

    // Per-line to_line/from_line agree with the stream form.
    for ev in &events {
        let line = ndjson::to_line(ev).unwrap();
        let back = ndjson::from_line(&line).unwrap();
        assert_eq!(&back, ev, "to_line/from_line must round-trip each event");
    }
}
