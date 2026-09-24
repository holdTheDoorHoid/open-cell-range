//! `ocr` — load a capture and replay it through the Open Cell Range engines.
//!
//! This is the phase-two seam from `DESIGN.md`: the same crates that run the
//! teaching simulation also analyse a real capture, because they are the same
//! code. Today it reads the project's NDJSON capture format and runs the passive
//! monitor over it. Importers for Rayhunter output, SCAT, QCSuper and GSMTAP pcap
//! come later and only need to emit this NDJSON.
//!
//! ## Implementer notes (stubbed; fill the bodies)
//! - Parse the NDJSON line shape from DESIGN.md section 3 into `ocr_air::AirEvent`.
//! - `ocr replay <file>` feeds events to `ocr_detect::Monitor` and prints
//!   findings; `ocr scenarios` lists the drill catalogue.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("scenarios") => {
            for id in ocr_scenario::ScenarioId::all() {
                println!("{}", id.slug());
            }
            ExitCode::SUCCESS
        }
        Some("replay") => {
            eprintln!("replay: not yet implemented (see DESIGN.md section 3)");
            ExitCode::FAILURE
        }
        _ => {
            eprintln!("usage: ocr <scenarios|replay <file.ndjson>>");
            ExitCode::FAILURE
        }
    }
}
