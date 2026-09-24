//! Attacker actors for Open Cell Range.
//!
//! Each actor drives a [`World`] the way a real attacker would — a rogue cell
//! that out-signals the network, a reject that forces a downgrade, a cipher-mode
//! command that turns encryption off. Actors change world state; **flags are
//! then awarded on that state**, never on the actor claiming success (see
//! `DESIGN.md`, "the rule that makes drills trustworthy").
//!
//! ## Implementer notes (stubbed; fill the bodies)
//! - An actor's `run` should leave observable `AirEvent`s behind, so `ocr-detect`
//!   has something to catch and the sandbox has something to show.
//! - Nothing here is carrier-specific or a working real-world exploit; it is the
//!   documented attack shape against the simulated stack. See `docs/ETHICS.md`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use ocr_air::World;

/// One attack, driving a world toward the state its flag predicate checks.
pub trait Attacker {
    /// Stable identifier used by scenarios and the UI.
    fn id(&self) -> &'static str;
    /// One-line human description.
    fn describe(&self) -> &'static str;
    /// Execute the attack against the world.
    fn run(&mut self, world: &mut World);
}

/// 2G: stand up a rogue BTS on the target PLMN with a strong signal, let the UE
/// camp, then send Identity Request (IMSI).
#[derive(Default)]
pub struct ImsiCatcher2g;

impl Attacker for ImsiCatcher2g {
    fn id(&self) -> &'static str {
        "imsi_catch_2g"
    }
    fn describe(&self) -> &'static str {
        "Rogue 2G cell requests the IMSI in cleartext"
    }
    fn run(&mut self, world: &mut World) {
        let _ = world;
        unimplemented!("stand up rogue BTS, camp UE, send Identity Request")
    }
}

/// 4G: block/reject LTE so the UE falls back to 2G, where Track 1 applies.
#[derive(Default)]
pub struct Downgrader;

impl Attacker for Downgrader {
    fn id(&self) -> &'static str {
        "downgrade_lte_to_2g"
    }
    fn describe(&self) -> &'static str {
        "Force bidding-down from LTE to GSM via unprotected reject"
    }
    fn run(&mut self, world: &mut World) {
        let _ = world;
        unimplemented!("inject pre-auth reject, drive UE to 2G")
    }
}

/// 2G: command A5/0 so traffic is unencrypted.
#[derive(Default)]
pub struct NullCipherForcer;

impl Attacker for NullCipherForcer {
    fn id(&self) -> &'static str {
        "force_null_cipher"
    }
    fn describe(&self) -> &'static str {
        "Command A5/0 so nothing is encrypted"
    }
    fn run(&mut self, world: &mut World) {
        let _ = world;
        unimplemented!("send CipherModeCommand(A5_0)")
    }
}

/// LTE: catch the IMSI via the cleartext Identity Request sent before the
/// security context exists.
#[derive(Default)]
pub struct ImsiCatcher4g;

impl Attacker for ImsiCatcher4g {
    fn id(&self) -> &'static str {
        "imsi_catch_4g"
    }
    fn describe(&self) -> &'static str {
        "Rogue eNodeB requests IMSI before security is established"
    }
    fn run(&mut self, world: &mut World) {
        let _ = world;
        unimplemented!("pre-security Identity Request over LTE")
    }
}

/// 5G: exploit a network configured for the null protection scheme, so the SUPI
/// is sent in the clear despite "SUCI being on".
#[derive(Default)]
pub struct SuciNullExploit;

impl Attacker for SuciNullExploit {
    fn id(&self) -> &'static str {
        "suci_null_scheme"
    }
    fn describe(&self) -> &'static str {
        "Recover SUPI when the null protection scheme is configured"
    }
    fn run(&mut self, world: &mut World) {
        let _ = world;
        unimplemented!("observe null-scheme SUCI, read SUPI")
    }
}

/// Every actor the range ships, for the sandbox picker and the scenario loader.
pub fn all() -> Vec<Box<dyn Attacker>> {
    unimplemented!("list every attacker actor")
}
