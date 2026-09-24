//! Deterministic cryptographic primitives for Open Cell Range.
//!
//! Everything here is `no_std` + `alloc` and takes its randomness from an
//! explicit [`SeededRng`]. There is **no** access to OS time or OS entropy: that
//! is the rule from `DESIGN.md` section 3 that makes every scenario reproducible
//! and lets the whole engine compile to `wasm32-unknown-unknown`.
//!
//! Subscriber keys used with these primitives are the published 3GPP test
//! vectors, never real ones (see `docs/ETHICS.md`).
//!
//! ## Implementer notes (this crate is stubbed; fill the bodies)
//! - MILENAGE follows 3GPP TS 35.206; validate `f1..f5`, `f1*`, `f5*` against
//!   the TS 35.207/35.208 test sets before wiring anything downstream.
//! - SUCI Profile A follows TS 33.501 Annex C.3 (Curve25519 + ANSI-X9.63 KDF
//!   with SHA-256 + AES-128-CTR + HMAC-SHA-256, 8-byte MAC). Validate against
//!   the Annex C worked example.
//! - Do not add a dependency that pulls in `std`, `getrandom`, or a system
//!   clock. If you think you need entropy, thread [`SeededRng`] instead.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

/// A 128-bit key or block, the width MILENAGE and the SUCI symmetric layer use.
pub type Key128 = [u8; 16];

/// A deterministic, seedable random source. The only source of "randomness" in
/// the whole engine. Not cryptographically strong against an adversary who knows
/// the seed — that is intentional; reproducibility is the requirement here, and
/// nothing real is ever protected by these bytes.
#[derive(Clone, Debug)]
pub struct SeededRng {
    #[allow(dead_code)]
    state: u64,
}

impl SeededRng {
    /// Create an RNG from a 64-bit seed. The same seed always yields the same
    /// stream.
    pub fn new(seed: u64) -> Self {
        // A real splitmix64 goes here; stubbed for now.
        Self { state: seed }
    }

    /// Next 64 bits of the stream.
    pub fn next_u64(&mut self) -> u64 {
        unimplemented!("splitmix64 step")
    }

    /// Fill `buf` with deterministic bytes.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        let _ = buf;
        unimplemented!("draw from next_u64")
    }
}

/// AES-128 in CTR mode. Used by the SUCI symmetric layer.
pub fn aes128_ctr(key: &Key128, iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let _ = (key, iv, data);
    unimplemented!("aes-128-ctr")
}

/// AES-128-CMAC. Used where a block-cipher MAC is needed.
pub fn aes128_cmac(key: &Key128, data: &[u8]) -> [u8; 16] {
    let _ = (key, data);
    unimplemented!("aes-128-cmac")
}

/// MILENAGE authentication functions (3GPP TS 35.206), parameterised by the
/// subscriber key `K` and the operator constant `OPc`.
///
/// This is the shared engine for GSM (via the 2G/3G interworking of A3/A8), LTE
/// EPS-AKA and 5G-AKA — the generation crates call into it rather than
/// re-implementing key derivation.
#[derive(Clone)]
pub struct Milenage {
    #[allow(dead_code)]
    k: Key128,
    #[allow(dead_code)]
    op_c: Key128,
}

/// The five MILENAGE outputs for one `RAND` challenge.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MilenageOut {
    /// f1: network authentication code (MAC-A), 8 bytes.
    pub mac_a: [u8; 8],
    /// f2: expected response (RES/XRES), 8 bytes.
    pub res: [u8; 8],
    /// f3: cipher key CK, 16 bytes.
    pub ck: Key128,
    /// f4: integrity key IK, 16 bytes.
    pub ik: Key128,
    /// f5: anonymity key AK, 6 bytes.
    pub ak: [u8; 6],
}

impl Milenage {
    /// Build from a subscriber key and OPc (the derived operator constant).
    pub fn new(k: Key128, op_c: Key128) -> Self {
        Self { k, op_c }
    }

    /// Derive OPc from K and the operator OP, for callers holding OP rather than
    /// OPc.
    pub fn op_c_from_op(k: &Key128, op: &Key128) -> Key128 {
        let _ = (k, op);
        unimplemented!("OPc = OP XOR E_K(OP)")
    }

    /// Run f1..f5 for a challenge and the sequence/AMF inputs f1 needs.
    pub fn compute(&self, rand: &Key128, sqn: &[u8; 6], amf: &[u8; 2]) -> MilenageOut {
        let _ = (rand, sqn, amf);
        unimplemented!("milenage f1..f5")
    }

    /// f1*: resynchronisation MAC (MAC-S), used in the AUTS path.
    pub fn f1_star(&self, rand: &Key128, sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 8] {
        let _ = (rand, sqn, amf);
        unimplemented!("milenage f1*")
    }

    /// f5*: resynchronisation anonymity key.
    pub fn f5_star(&self, rand: &Key128) -> [u8; 6] {
        let _ = rand;
        unimplemented!("milenage f5*")
    }
}

/// SUCI concealment (5G), the fix the whole teaching arc builds toward.
pub mod suci {
    use super::SeededRng;
    use alloc::vec::Vec;

    /// The protection scheme applied to the SUPI before it goes on the air.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ProtectionScheme {
        /// Scheme 0 — the SUPI is sent in the clear. Spec-legal and a teaching
        /// centrepiece: the "fix" that can be configured off.
        Null,
        /// Profile A — ECIES over Curve25519 (TS 33.501 Annex C.3.4.1).
        ProfileA,
    }

    /// The home network's ECIES key pair. Only the public half is provisioned on
    /// the device; the private half lives in the (simulated) home network.
    #[derive(Clone)]
    pub struct HomeNetworkKeyPair {
        pub public_key: [u8; 32],
        pub private_key: [u8; 32],
    }

    impl HomeNetworkKeyPair {
        /// Deterministically derive a key pair from the RNG, so a scenario's home
        /// network is stable across runs.
        pub fn generate(rng: &mut SeededRng) -> Self {
            let _ = rng;
            unimplemented!("x25519 keypair from seeded rng")
        }
    }

    /// The concealed output: ephemeral public key, ciphertext, and MAC tag, plus
    /// the scheme used so a reader knows how to interpret it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Concealed {
        pub scheme: ProtectionScheme,
        pub eph_public_key: Vec<u8>,
        pub ciphertext: Vec<u8>,
        pub mac: Vec<u8>,
    }

    /// Conceal the MSIN bytes of a SUPI with the home network public key.
    ///
    /// For [`ProtectionScheme::Null`] the "ciphertext" is the plaintext MSIN and
    /// there is no ephemeral key or MAC — that is the whole point of the null
    /// scheme.
    pub fn conceal(
        scheme: ProtectionScheme,
        home_pub: &[u8; 32],
        msin: &[u8],
        rng: &mut SeededRng,
    ) -> Concealed {
        let _ = (scheme, home_pub, msin, rng);
        unimplemented!("ecies profile A / null conceal")
    }

    /// Recover the MSIN from a concealed value, as the home network would.
    /// Returns `None` if the MAC does not verify.
    pub fn deconceal(home_priv: &[u8; 32], c: &Concealed) -> Option<Vec<u8>> {
        let _ = (home_priv, c);
        unimplemented!("ecies profile A / null deconceal")
    }
}
