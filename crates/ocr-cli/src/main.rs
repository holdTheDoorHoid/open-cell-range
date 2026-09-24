//! `ocr` — run Open Cell Range drills over the terminal, and load/replay a
//! capture through the same engines.
//!
//! This is the phase-two seam from `DESIGN.md`: the same crates that run the
//! browser's teaching simulation also analyse a capture, because they are the
//! same code. `ocr run` drives a scenario headline-to-finish exactly the way
//! the site's engine does (`build` -> `run_headline` -> `Monitor::observe_all`
//! -> `Scenario::evaluate`) and prints the drill as readable text. `ocr record`
//! writes that same run's `World::events()` as NDJSON (see `src/ndjson.rs` for
//! the exact shape and why it differs from a hardware capture's raw bytes);
//! `ocr replay` reads that file back into `AirEvent`s and runs a fresh
//! `Monitor` over them, proving the capture seam reaches the same conclusions
//! as the live run.

mod ndjson;

use std::io::BufReader;
use std::process::ExitCode;

use ocr_air::{AirEvent, Direction};
use ocr_detect::{Monitor, Severity};
use ocr_scenario::{Scenario, ScenarioId};

fn find_scenario(slug: &str) -> Option<ScenarioId> {
    ScenarioId::all()
        .iter()
        .copied()
        .find(|id| id.slug() == slug)
}

fn dir_arrow(d: Direction) -> &'static str {
    match d {
        Direction::NetToUe => "NET->UE",
        Direction::UeToNet => "UE->NET",
        Direction::Observed => "OBSERVED",
    }
}

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
    }
}

/// Build a scenario, run its headline attack, and observe the whole air with a
/// fresh monitor — the engine flow `site/ENGINE-API.md` calls `load` +
/// `runAttack`. Shared by `ocr run` and the tests below so both exercise the
/// exact same path.
fn run_scenario_drill(id: ScenarioId) -> (Scenario, Monitor) {
    let mut scenario = ocr_scenario::build(id);
    scenario.run_headline();
    let mut monitor = Monitor::new();
    monitor.observe_all(scenario.world.events());
    (scenario, monitor)
}

fn print_air_log(events: &[AirEvent]) {
    println!("-- Air log ({} events) --", events.len());
    if events.is_empty() {
        println!("(none)");
    }
    for ev in events {
        println!(
            "{:>10}us  {:<8} {}",
            ev.t_us,
            dir_arrow(ev.dir),
            ocr_air::describe(ev)
        );
    }
}

fn print_findings(monitor: &Monitor) {
    let findings = monitor.findings();
    println!("\n-- Monitor findings ({}) --", findings.len());
    if findings.is_empty() {
        println!("(none)");
    }
    for f in findings {
        println!(
            "[{:<6}] {} @ t={}us",
            severity_str(f.severity),
            f.kind,
            f.t_us
        );
        println!("    {}", f.detail);
    }
}

fn print_drill(scenario: &Scenario, monitor: &Monitor) {
    println!(
        "=== {} ({}, track: {}) ===",
        scenario.title,
        scenario.id.slug(),
        scenario.id.track()
    );
    println!("{}\n", scenario.brief);

    print_air_log(scenario.world.events());
    print_findings(monitor);

    let flag_states = scenario.evaluate(monitor);
    println!("\n-- Flags --");
    for state in &flag_states {
        let title = scenario
            .flags
            .iter()
            .find(|f| f.id == state.id.as_str())
            .map(|f| f.title.as_str())
            .unwrap_or("");
        let mark = if state.captured { 'x' } else { ' ' };
        println!("[{mark}] {}  {title}", state.id);
    }
}

fn cmd_scenarios() -> ExitCode {
    println!("{:<26}{:<8}title", "slug", "track");
    for &id in ScenarioId::all() {
        let scenario = ocr_scenario::build(id);
        println!("{:<26}{:<8}{}", id.slug(), id.track(), scenario.title);
    }
    ExitCode::SUCCESS
}

fn cmd_run(slug: &str) -> ExitCode {
    let Some(id) = find_scenario(slug) else {
        eprintln!("ocr run: unknown scenario '{slug}' (see `ocr scenarios`)");
        return ExitCode::FAILURE;
    };
    let (scenario, monitor) = run_scenario_drill(id);
    print_drill(&scenario, &monitor);
    ExitCode::SUCCESS
}

fn cmd_record(slug: &str, path: Option<&str>) -> ExitCode {
    let Some(id) = find_scenario(slug) else {
        eprintln!("ocr record: unknown scenario '{slug}' (see `ocr scenarios`)");
        return ExitCode::FAILURE;
    };
    let mut scenario = ocr_scenario::build(id);
    scenario.run_headline();
    let events = scenario.world.events();

    let result: Result<(), ndjson::NdjsonError> = match path {
        Some(p) => match std::fs::File::create(p) {
            Ok(mut f) => ndjson::write_events(events, &mut f),
            Err(e) => Err(ndjson::NdjsonError::from(e)),
        },
        None => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            ndjson::write_events(events, &mut lock)
        }
    };

    match result {
        Ok(()) => {
            if let Some(p) = path {
                eprintln!("wrote {} events to {p}", events.len());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ocr record: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_replay(path: &str) -> ExitCode {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ocr replay: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let events = match ndjson::read_events(BufReader::new(file)) {
        Ok(events) => events,
        Err(e) => {
            eprintln!("ocr replay: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("=== replay: {path} ({} events) ===\n", events.len());
    print_air_log(&events);

    let mut monitor = Monitor::new();
    monitor.observe_all(&events);
    print_findings(&monitor);

    ExitCode::SUCCESS
}

fn print_usage() {
    eprintln!("usage:");
    eprintln!("  ocr scenarios");
    eprintln!("  ocr run <slug>");
    eprintln!("  ocr record <slug> [file.ndjson]     (writes stdout if no file given)");
    eprintln!("  ocr replay <file.ndjson>");
    eprintln!();
    eprintln!("run `ocr scenarios` to list valid <slug> values.");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("scenarios") => cmd_scenarios(),
        Some("run") => match args.get(2) {
            Some(slug) => cmd_run(slug),
            None => {
                eprintln!("usage: ocr run <slug>");
                ExitCode::FAILURE
            }
        },
        Some("record") => match args.get(2) {
            Some(slug) => cmd_record(slug, args.get(3).map(String::as_str)),
            None => {
                eprintln!("usage: ocr record <slug> [file.ndjson]");
                ExitCode::FAILURE
            }
        },
        Some("replay") => match args.get(2) {
            Some(path) => cmd_replay(path),
            None => {
                eprintln!("usage: ocr replay <file.ndjson>");
                ExitCode::FAILURE
            }
        },
        _ => {
            print_usage();
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_scenario_resolves_every_published_slug() {
        for &id in ScenarioId::all() {
            assert_eq!(find_scenario(id.slug()), Some(id));
        }
        assert_eq!(find_scenario("no-such-slug"), None);
    }

    /// `ocr run` / `ocr record` must handle every shipped scenario without
    /// panicking: build, run the headline, observe, evaluate flags, and
    /// serialize the whole event stream to NDJSON.
    #[test]
    fn every_scenario_runs_and_records_without_panicking() {
        for &id in ScenarioId::all() {
            let (scenario, monitor) = run_scenario_drill(id);
            assert!(
                !scenario.world.events().is_empty(),
                "{id:?} produced no events"
            );
            // Flags must evaluate without panicking, whatever the outcome.
            let states = scenario.evaluate(&monitor);
            assert_eq!(states.len(), scenario.flags.len());

            // The record path: the whole event stream must serialize to NDJSON.
            let mut buf = Vec::new();
            ndjson::write_events(scenario.world.events(), &mut buf)
                .unwrap_or_else(|e| panic!("{id:?} failed to record: {e}"));
            assert!(!buf.is_empty());

            // And it must read back into the exact same events (the replay path).
            let replayed = ndjson::read_events(&buf[..])
                .unwrap_or_else(|e| panic!("{id:?} failed to replay: {e}"));
            assert_eq!(replayed, scenario.world.events());
        }
    }
}
