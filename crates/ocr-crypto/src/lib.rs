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

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use alloc::vec::Vec;

/// A 128-bit key or block, the width MILENAGE and the SUCI symmetric layer use.
pub type Key128 = [u8; 16];

/// A deterministic, seedable random source. The only source of "randomness" in
/// the whole engine. Not cryptographically strong against an adversary who knows
/// the seed — that is intentional; reproducibility is the requirement here, and
/// nothing real is ever protected by these bytes.
///
/// The generator is `splitmix64` (Vigna): a single additive step through a
/// 64-bit state followed by an avalanche mix. It is fast, has a full 2^64
/// period, and — crucially for us — is trivially portable, so the exact same
/// byte stream comes out on `wasm32`, on a workstation, and on CI.
#[derive(Clone, Debug)]
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    /// Create an RNG from a 64-bit seed. The same seed always yields the same
    /// stream.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Next 64 bits of the stream (splitmix64).
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Fill `buf` with deterministic bytes drawn from [`SeededRng::next_u64`].
    ///
    /// Words are emitted little-endian; a trailing partial word takes as many
    /// low bytes as needed. The mapping is fixed so the stream is stable.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let word = self.next_u64().to_le_bytes();
            let n = core::cmp::min(8, buf.len() - i);
            buf[i..i + n].copy_from_slice(&word[..n]);
            i += n;
        }
    }
}

/// AES-128 single-block encryption, `E_K[input]`. The kernel MILENAGE is built
/// on. Kept private: callers want the named functions, not a raw block cipher.
fn aes128_encrypt_block(key: &Key128, input: &Key128) -> Key128 {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(input);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    out
}

/// AES-128 in CTR mode (128-bit big-endian counter). Used by the SUCI symmetric
/// layer. Encryption and decryption are the same operation.
pub fn aes128_ctr(key: &Key128, iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    let mut cipher =
        ctr::Ctr128BE::<Aes128>::new(GenericArray::from_slice(key), GenericArray::from_slice(iv));
    let mut buf = data.to_vec();
    cipher.apply_keystream(&mut buf);
    buf
}

/// AES-128-CMAC. Used where a block-cipher MAC is needed.
pub fn aes128_cmac(key: &Key128, data: &[u8]) -> [u8; 16] {
    use cmac::{Cmac, Mac};
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key).expect("cmac key is 16 bytes");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    out
}

// ---- MILENAGE (3GPP TS 35.206) -------------------------------------------

/// XOR `b` into `a`, in place, over a full 128-bit block.
fn xor128(a: &mut Key128, b: &Key128) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= *y;
    }
}

/// Cyclic left rotation of a 128-bit value by `n` **bytes** (all MILENAGE
/// rotation constants r1..r5 are multiples of 8 bits, so byte rotation covers
/// every case). Bit 0 is the most significant, so a left rotation by `n` bytes
/// moves the byte at index `n` to index 0: `out[i] = x[(i + n) mod 16]`.
fn rot_bytes(x: &Key128, n: usize) -> Key128 {
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = x[(i + n) % 16];
    }
    out
}

/// MILENAGE authentication functions (3GPP TS 35.206), parameterised by the
/// subscriber key `K` and the operator constant `OPc`.
///
/// This is the shared engine for GSM (via the 2G/3G interworking of A3/A8), LTE
/// EPS-AKA and 5G-AKA — the generation crates call into it rather than
/// re-implementing key derivation.
#[derive(Clone)]
pub struct Milenage {
    k: Key128,
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
    /// OPc. `OPc = OP XOR E_K[OP]`.
    pub fn op_c_from_op(k: &Key128, op: &Key128) -> Key128 {
        let mut op_c = aes128_encrypt_block(k, op);
        xor128(&mut op_c, op);
        op_c
    }

    /// `E_K[input]` under this subscriber's key.
    fn e_k(&self, input: &Key128) -> Key128 {
        aes128_encrypt_block(&self.k, input)
    }

    /// `TEMP = E_K[RAND XOR OPc]`, shared by every output function.
    fn temp(&self, rand: &Key128) -> Key128 {
        let mut x = *rand;
        xor128(&mut x, &self.op_c);
        self.e_k(&x)
    }

    /// `OUT1 = E_K[TEMP XOR rot(IN1 XOR OPc, r1) XOR c1] XOR OPc`, where `IN1`
    /// packs SQN||AMF twice. The high 64 bits are MAC-A (f1), the low 64 bits
    /// are MAC-S (f1*). Shared by [`Milenage::compute`] and [`Milenage::f1_star`].
    fn out1(&self, rand: &Key128, sqn: &[u8; 6], amf: &[u8; 2]) -> Key128 {
        let temp = self.temp(rand);

        // IN1 = SQN || AMF || SQN || AMF (6 + 2 + 6 + 2 = 16 bytes).
        let mut in1 = [0u8; 16];
        in1[0..6].copy_from_slice(sqn);
        in1[6..8].copy_from_slice(amf);
        in1[8..14].copy_from_slice(sqn);
        in1[14..16].copy_from_slice(amf);

        // rot(IN1 XOR OPc, r1 = 64 bits = 8 bytes); c1 is all-zero.
        xor128(&mut in1, &self.op_c);
        let rotated = rot_bytes(&in1, 8);

        let mut block = temp;
        xor128(&mut block, &rotated);
        let mut out = self.e_k(&block);
        xor128(&mut out, &self.op_c);
        out
    }

    /// `OUT_n = E_K[rot(TEMP XOR OPc, r) XOR c] XOR OPc` for the f2/f3/f4/f5 and
    /// f5* branches. `rot` is in bytes; `c_low` is XORed into the last byte
    /// (constants c2..c5 are 1, 2, 4, 8).
    fn out_n(&self, rand: &Key128, rot: usize, c_low: u8) -> Key128 {
        let temp = self.temp(rand);
        let mut block = temp;
        xor128(&mut block, &self.op_c);
        let mut block = rot_bytes(&block, rot);
        block[15] ^= c_low;
        let mut out = self.e_k(&block);
        xor128(&mut out, &self.op_c);
        out
    }

    /// Run f1..f5 for a challenge and the sequence/AMF inputs f1 needs.
    pub fn compute(&self, rand: &Key128, sqn: &[u8; 6], amf: &[u8; 2]) -> MilenageOut {
        let out1 = self.out1(rand, sqn, amf);
        // OUT2: r2 = 0, c2 = 1. f5 = OUT2[0..6], f2 = OUT2[8..16].
        let out2 = self.out_n(rand, 0, 1);
        // OUT3: r3 = 96 bits? No — r3 = 32 bits = 4 bytes, c3 = 2. f3 = OUT3.
        let out3 = self.out_n(rand, 4, 2);
        // OUT4: r4 = 64 bits = 8 bytes, c4 = 4. f4 = OUT4.
        let out4 = self.out_n(rand, 8, 4);

        let mut mac_a = [0u8; 8];
        mac_a.copy_from_slice(&out1[0..8]);
        let mut res = [0u8; 8];
        res.copy_from_slice(&out2[8..16]);
        let mut ak = [0u8; 6];
        ak.copy_from_slice(&out2[0..6]);

        MilenageOut {
            mac_a,
            res,
            ck: out3,
            ik: out4,
            ak,
        }
    }

    /// f1*: resynchronisation MAC (MAC-S), used in the AUTS path. It is the low
    /// 64 bits of the same OUT1 that produces MAC-A.
    pub fn f1_star(&self, rand: &Key128, sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 8] {
        let out1 = self.out1(rand, sqn, amf);
        let mut mac_s = [0u8; 8];
        mac_s.copy_from_slice(&out1[8..16]);
        mac_s
    }

    /// f5*: resynchronisation anonymity key. `OUT5` with r5 = 96 bits (12 bytes)
    /// and c5 = 8; AK* is its high 48 bits.
    pub fn f5_star(&self, rand: &Key128) -> [u8; 6] {
        let out5 = self.out_n(rand, 12, 8);
        let mut ak = [0u8; 6];
        ak.copy_from_slice(&out5[0..6]);
        ak
    }
}

/// SUCI concealment (5G), the fix the whole teaching arc builds toward.
pub mod suci {
    use super::{aes128_ctr, SeededRng};
    use alloc::vec::Vec;
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    use x25519_dalek::{PublicKey, StaticSecret};

    /// Profile A KDF/output sizes (TS 33.501 Annex C.3.4.1): AES-128 key,
    /// 16-byte initial counter block, 32-byte HMAC-SHA-256 key, 8-byte tag.
    const PROFILE_A_ENC_KEY_LEN: usize = 16;
    const PROFILE_A_ICB_LEN: usize = 16;
    const PROFILE_A_MAC_KEY_LEN: usize = 32;
    const PROFILE_A_MAC_LEN: usize = 8;
    const KDF_OUT_LEN: usize = PROFILE_A_ENC_KEY_LEN + PROFILE_A_ICB_LEN + PROFILE_A_MAC_KEY_LEN;

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
        /// network is stable across runs. The private key is 32 seeded bytes;
        /// X25519 clamps them when a shared secret is computed.
        pub fn generate(rng: &mut SeededRng) -> Self {
            let mut sk = [0u8; 32];
            rng.fill_bytes(&mut sk);
            let secret = StaticSecret::from(sk);
            let public = PublicKey::from(&secret);
            Self {
                public_key: public.to_bytes(),
                private_key: secret.to_bytes(),
            }
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

    /// ANSI-X9.63 key derivation function with SHA-256 (TS 33.501 Annex C.3.2).
    ///
    /// `K_i = SHA-256(Z || I2OSP(i, 4) || SharedInfo)` for i = 1, 2, ...; the
    /// output is the leftmost `out_len` octets of `K_1 || K_2 || ...`. For SUCI
    /// Profile A, `Z` is the X25519 shared secret and `SharedInfo` is the
    /// ephemeral public key.
    fn ansi_x963_kdf(z: &[u8], shared_info: &[u8], out_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(out_len);
        let mut counter: u32 = 1;
        while out.len() < out_len {
            let mut hasher = Sha256::new();
            hasher.update(z);
            hasher.update(counter.to_be_bytes());
            hasher.update(shared_info);
            out.extend_from_slice(&hasher.finalize());
            counter = counter.wrapping_add(1);
        }
        out.truncate(out_len);
        out
    }

    /// Split KDF output into (enc key, ICB, MAC key).
    fn profile_a_keys(kdf: &[u8]) -> (super::Key128, [u8; 16], [u8; 32]) {
        let mut enc_key = [0u8; 16];
        enc_key.copy_from_slice(&kdf[0..PROFILE_A_ENC_KEY_LEN]);
        let mut icb = [0u8; 16];
        icb.copy_from_slice(&kdf[PROFILE_A_ENC_KEY_LEN..PROFILE_A_ENC_KEY_LEN + PROFILE_A_ICB_LEN]);
        let mut mac_key = [0u8; 32];
        mac_key.copy_from_slice(&kdf[PROFILE_A_ENC_KEY_LEN + PROFILE_A_ICB_LEN..KDF_OUT_LEN]);
        (enc_key, icb, mac_key)
    }

    /// Conceal `msin` under Profile A with a chosen ephemeral secret. Private:
    /// the public API draws the ephemeral secret from the seeded RNG. Exposed to
    /// tests so the TS 33.501 Annex C.4 exact vector (fixed ephemeral key) can be
    /// reproduced.
    fn conceal_profile_a(home_pub: &[u8; 32], msin: &[u8], eph_secret: [u8; 32]) -> Concealed {
        let eph_secret = StaticSecret::from(eph_secret);
        let eph_public = PublicKey::from(&eph_secret);
        let home_public = PublicKey::from(*home_pub);
        let shared = eph_secret.diffie_hellman(&home_public);

        let kdf = ansi_x963_kdf(shared.as_bytes(), eph_public.as_bytes(), KDF_OUT_LEN);
        let (enc_key, icb, mac_key) = profile_a_keys(&kdf);

        let ciphertext = aes128_ctr(&enc_key, &icb, msin);

        let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key).expect("hmac key length");
        hmac.update(&ciphertext);
        let full = hmac.finalize().into_bytes();

        Concealed {
            scheme: ProtectionScheme::ProfileA,
            eph_public_key: eph_public.to_bytes().to_vec(),
            ciphertext,
            mac: full[..PROFILE_A_MAC_LEN].to_vec(),
        }
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
        match scheme {
            ProtectionScheme::Null => Concealed {
                scheme: ProtectionScheme::Null,
                eph_public_key: Vec::new(),
                ciphertext: msin.to_vec(),
                mac: Vec::new(),
            },
            ProtectionScheme::ProfileA => {
                let mut eph_secret = [0u8; 32];
                rng.fill_bytes(&mut eph_secret);
                conceal_profile_a(home_pub, msin, eph_secret)
            }
        }
    }

    /// Recover the MSIN from a concealed value, as the home network would.
    /// Returns `None` if the MAC does not verify.
    pub fn deconceal(home_priv: &[u8; 32], c: &Concealed) -> Option<Vec<u8>> {
        match c.scheme {
            ProtectionScheme::Null => Some(c.ciphertext.clone()),
            ProtectionScheme::ProfileA => {
                let eph_public_bytes: [u8; 32] = c.eph_public_key.as_slice().try_into().ok()?;
                if c.mac.len() != PROFILE_A_MAC_LEN {
                    return None;
                }

                let home_secret = StaticSecret::from(*home_priv);
                let eph_public = PublicKey::from(eph_public_bytes);
                let shared = home_secret.diffie_hellman(&eph_public);

                let kdf = ansi_x963_kdf(shared.as_bytes(), &eph_public_bytes, KDF_OUT_LEN);
                let (enc_key, icb, mac_key) = profile_a_keys(&kdf);

                // Verify the 8-byte truncated HMAC before releasing plaintext.
                let mut hmac =
                    <Hmac<Sha256> as Mac>::new_from_slice(&mac_key).expect("hmac key length");
                hmac.update(&c.ciphertext);
                hmac.verify_truncated_left(&c.mac).ok()?;

                Some(aes128_ctr(&enc_key, &icb, &c.ciphertext))
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn hex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }

        fn arr32(s: &str) -> [u8; 32] {
            hex(s).try_into().unwrap()
        }

        #[test]
        fn null_scheme_is_passthrough() {
            let mut rng = SeededRng::new(1);
            let home = HomeNetworkKeyPair::generate(&mut rng);
            let msin = [0u8, 0, 1, 0, 0, 2, 0, 8, 6];
            let c = conceal(ProtectionScheme::Null, &home.public_key, &msin, &mut rng);
            assert!(c.eph_public_key.is_empty());
            assert!(c.mac.is_empty());
            assert_eq!(c.ciphertext, msin);
            let back = deconceal(&home.private_key, &c).unwrap();
            assert_eq!(back, msin);
        }

        #[test]
        fn profile_a_round_trip() {
            let mut rng = SeededRng::new(0xC0FFEE);
            let home = HomeNetworkKeyPair::generate(&mut rng);
            let msin = [0u8, 0, 1, 0, 0, 2, 0, 8, 6, 5, 4, 3];
            let c = conceal(
                ProtectionScheme::ProfileA,
                &home.public_key,
                &msin,
                &mut rng,
            );
            assert_eq!(c.scheme, ProtectionScheme::ProfileA);
            assert_eq!(c.eph_public_key.len(), 32);
            assert_eq!(c.mac.len(), 8);
            assert_ne!(c.ciphertext, msin); // actually concealed
            let back = deconceal(&home.private_key, &c).unwrap();
            assert_eq!(back, msin);
        }

        #[test]
        fn profile_a_tamper_fails() {
            let mut rng = SeededRng::new(7);
            let home = HomeNetworkKeyPair::generate(&mut rng);
            let msin = [1u8, 2, 3, 4, 5];
            let mut c = conceal(
                ProtectionScheme::ProfileA,
                &home.public_key,
                &msin,
                &mut rng,
            );
            c.ciphertext[0] ^= 0x01;
            assert!(deconceal(&home.private_key, &c).is_none());
        }

        #[test]
        fn profile_a_wrong_key_fails() {
            let mut rng = SeededRng::new(9);
            let home = HomeNetworkKeyPair::generate(&mut rng);
            let other = HomeNetworkKeyPair::generate(&mut rng);
            let msin = [1u8, 2, 3, 4, 5];
            let c = conceal(
                ProtectionScheme::ProfileA,
                &home.public_key,
                &msin,
                &mut rng,
            );
            assert!(deconceal(&other.private_key, &c).is_none());
        }

        /// TS 33.501 Annex C.4 Profile A worked example (as reproduced in the
        /// free5GC UDM `suci` test data). This validates the full ECDH +
        /// ANSI-X9.63(SHA-256) KDF + AES-128-CTR + HMAC-SHA-256 path against the
        /// published vector: the MAC verifying at all proves the ECDH, KDF and
        /// HMAC are exact, and the recovered plaintext proves the CTR/ICB path.
        #[test]
        fn profile_a_ts33501_annex_c4_vector() {
            let home_priv =
                arr32("c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d");
            let home_pub =
                arr32("5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650");

            // The public key really is the X25519 image of the private key.
            let derived_pub = PublicKey::from(&StaticSecret::from(home_priv));
            assert_eq!(derived_pub.to_bytes(), home_pub);

            let eph_pub = hex("b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d");
            let ciphertext = hex("cb02352410");
            let mac = hex("cddd9e730ef3fa87");

            let concealed = Concealed {
                scheme: ProtectionScheme::ProfileA,
                eph_public_key: eph_pub,
                ciphertext,
                mac,
            };

            let plaintext = deconceal(&home_priv, &concealed).expect("Annex C.4 MAC must verify");
            // MSIN 001002086 in TS 24.501 swapped-BCD with an 0xF filler nibble.
            assert_eq!(plaintext, hex("00012080f6"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr16(s: &str) -> [u8; 16] {
        hex(s).try_into().unwrap()
    }
    fn arr8(s: &str) -> [u8; 8] {
        hex(s).try_into().unwrap()
    }
    fn arr6(s: &str) -> [u8; 6] {
        hex(s).try_into().unwrap()
    }

    #[test]
    fn seeded_rng_is_deterministic() {
        let mut a = SeededRng::new(42);
        let mut b = SeededRng::new(42);
        assert_eq!(a.next_u64(), b.next_u64());
        let mut buf1 = [0u8; 40];
        let mut buf2 = [0u8; 40];
        a.fill_bytes(&mut buf1);
        b.fill_bytes(&mut buf2);
        assert_eq!(buf1, buf2);

        // Different seed => different stream (overwhelmingly likely).
        let mut c = SeededRng::new(43);
        assert_ne!(a.next_u64(), c.next_u64());
    }

    #[test]
    fn splitmix64_known_values() {
        // splitmix64(seed=0) reference stream (Vigna).
        let mut r = SeededRng::new(0);
        assert_eq!(r.next_u64(), 0xE220A8397B1DCDAF);
        assert_eq!(r.next_u64(), 0x6E789E6AA1B965F4);
        assert_eq!(r.next_u64(), 0x06C45D188009454F);
    }

    #[test]
    fn aes128_ctr_round_trip() {
        let key = arr16("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = arr16("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let data = b"open cell range ctr test payload!!";
        let ct = aes128_ctr(&key, &iv, data);
        assert_ne!(&ct[..], &data[..]);
        let pt = aes128_ctr(&key, &iv, &ct);
        assert_eq!(&pt[..], &data[..]);
    }

    #[test]
    fn aes128_ctr_nist_sp800_38a_f5_1() {
        // NIST SP 800-38A F.5.1 CTR-AES128 first block.
        let key = arr16("2b7e151628aed2a6abf7158809cf4f3c");
        let ctr0 = arr16("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");
        let ct = aes128_ctr(&key, &ctr0, &pt);
        assert_eq!(ct, hex("874d6191b620e3261bef6864990db6ce"));
    }

    #[test]
    fn aes128_cmac_nist_examples() {
        // NIST SP 800-38B worked examples (AES-128).
        let key = arr16("2b7e151628aed2a6abf7158809cf4f3c");
        // Empty message.
        assert_eq!(
            aes128_cmac(&key, &[]),
            arr16("bb1d6929e95937287fa37d129b756746")
        );
        // 16-byte message.
        let msg = hex("6bc1bee22e409f96e93d7e117393172a");
        assert_eq!(
            aes128_cmac(&key, &msg),
            arr16("070a16b46b4d4144f79bdd9dd04a287c")
        );
    }

    // ---- MILENAGE test sets from 3GPP TS 35.208 ----

    struct MilenageVector {
        k: &'static str,
        op: &'static str,
        op_c: &'static str,
        rand: &'static str,
        sqn: &'static str,
        amf: &'static str,
        f1: &'static str,
        f1_star: &'static str,
        f2: &'static str,
        f3: &'static str,
        f4: &'static str,
        f5: &'static str,
        f5_star: &'static str,
    }

    fn check_vector(v: &MilenageVector) {
        let k = arr16(v.k);
        let op = arr16(v.op);
        let op_c = arr16(v.op_c);
        let rand = arr16(v.rand);
        let sqn = arr6(v.sqn);
        let amf: [u8; 2] = hex(v.amf).try_into().unwrap();

        // OPc derivation matches the published constant.
        assert_eq!(Milenage::op_c_from_op(&k, &op), op_c, "OPc mismatch");

        let m = Milenage::new(k, op_c);
        let out = m.compute(&rand, &sqn, &amf);

        assert_eq!(out.mac_a, arr8(v.f1), "f1 (MAC-A) mismatch");
        assert_eq!(out.res, arr8(v.f2), "f2 (RES) mismatch");
        assert_eq!(out.ck, arr16(v.f3), "f3 (CK) mismatch");
        assert_eq!(out.ik, arr16(v.f4), "f4 (IK) mismatch");
        assert_eq!(out.ak, arr6(v.f5), "f5 (AK) mismatch");
        assert_eq!(
            m.f1_star(&rand, &sqn, &amf),
            arr8(v.f1_star),
            "f1* mismatch"
        );
        assert_eq!(m.f5_star(&rand), arr6(v.f5_star), "f5* mismatch");
    }

    #[test]
    fn milenage_test_set_1() {
        check_vector(&MilenageVector {
            k: "465b5ce8b199b49faa5f0a2ee238a6bc",
            op: "cdc202d5123e20f62b6d676ac72cb318",
            op_c: "cd63cb71954a9f4e48a5994e37a02baf",
            rand: "23553cbe9637a89d218ae64dae47bf35",
            sqn: "ff9bb4d0b607",
            amf: "b9b9",
            f1: "4a9ffac354dfafb3",
            f1_star: "01cfaf9ec4e871e9",
            f2: "a54211d5e3ba50bf",
            f3: "b40ba9a3c58b2a05bbf0d987b21bf8cb",
            f4: "f769bcd751044604127672711c6d3441",
            f5: "aa689c648370",
            f5_star: "451e8beca43b",
        });
    }

    #[test]
    fn milenage_test_set_3() {
        check_vector(&MilenageVector {
            k: "fec86ba6eb707ed08905757b1bb44b8f",
            op: "dbc59adcb6f9a0ef735477b7fadf8374",
            op_c: "1006020f0a478bf6b699f15c062e42b3",
            rand: "9f7c8d021accf4db213ccff0c7f71a6a",
            sqn: "9d0277595ffc",
            amf: "725c",
            f1: "9cabc3e99baf7281",
            f1_star: "95814ba2b3044324",
            f2: "8011c48c0c214ed2",
            f3: "5dbdbb2954e8f3cde665b046179a5098",
            f4: "59a92d3b476a0443487055cf88b2307b",
            f5: "33484dc2136b",
            f5_star: "deacdd848cc6",
        });
    }

    #[test]
    fn milenage_test_set_4() {
        check_vector(&MilenageVector {
            k: "9e5944aea94b81165c82fbf9f32db751",
            op: "223014c5806694c007ca1eeef57f004f",
            op_c: "a64a507ae1a2a98bb88eb4210135dc87",
            rand: "ce83dbc54ac0274a157c17f80d017bd6",
            sqn: "0b604a81eca8",
            amf: "9e09",
            f1: "74a58220cba84c49",
            f1_star: "ac2cc74a96871837",
            f2: "f365cd683cd92e96",
            f3: "e203edb3971574f5a94b0d61b816345d",
            f4: "0c4524adeac041c4dd830d20854fc46b",
            f5: "f0b9c08ad02e",
            f5_star: "6085a86c6f63",
        });
    }

    #[test]
    fn milenage_test_set_5() {
        check_vector(&MilenageVector {
            k: "4ab1deb05ca6ceb051fc98e77d026a84",
            op: "2d16c5cd1fdf6b22383584e3bef2a8d8",
            op_c: "dcf07cbd51855290b92a07a9891e523e",
            rand: "74b0cd6031a1c8339b2b6ce2b8c4a186",
            sqn: "e880a1b580b6",
            amf: "9f07",
            f1: "49e785dd12626ef2",
            f1_star: "9e85790336bb3fa2",
            f2: "5860fc1bce351e7e",
            f3: "7657766b373d1c2138f307e3de9242f9",
            f4: "1c42e960d89b8fa99f2744e0708ccb53",
            f5: "31e11a609118",
            f5_star: "fe2555e54aa9",
        });
    }
}
