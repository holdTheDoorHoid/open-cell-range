//! The native NDJSON capture format — now owned by `ocr-import` and re-exported
//! here so `ocr record`, `ocr replay`, and `ocr import` all read and write the
//! exact same shape. Nothing about the on-disk format changed; the definition just
//! moved next to the other importers (see `ocr_import::ndjson` for the full docs).
//!
//! The scenario-level round-trip tests stay here, because they exercise the *whole*
//! phase-two seam — record every scenario, replay it, and confirm the monitor draws
//! the same conclusions — which needs `ocr-scenario` and `ocr-detect` (deps of the
//! CLI, not of `ocr-import`).

pub use ocr_import::ndjson::*;

#[cfg(test)]
mod tests {
    use super::{read_events, write_events};
    use ocr_detect::Monitor;
    use ocr_scenario::ScenarioId;

    fn finding_kinds(monitor: &Monitor) -> Vec<ocr_detect::FindingKind> {
        monitor.findings().iter().map(|f| f.kind).collect()
    }

    /// The headline round-trip proof: record every scenario's air to NDJSON, read
    /// it back, and the events must be byte-for-byte identical.
    #[test]
    fn round_trip_preserves_events_for_every_scenario() {
        for &id in ScenarioId::all() {
            let mut scenario = ocr_scenario::build(id);
            scenario.run_headline();
            let events = scenario.world.events();
            assert!(
                !events.is_empty(),
                "{id:?} produced no events to round-trip"
            );

            let mut buf = Vec::new();
            write_events(events, &mut buf).expect("write_events must not fail");
            let parsed = read_events(&buf[..]).expect("read_events must parse what we wrote");

            assert_eq!(
                events,
                &parsed[..],
                "{id:?} did not round-trip byte for byte"
            );
        }
    }

    /// The point of the seam: a monitor run over the replayed capture must raise
    /// exactly the same finding kinds as one run directly over the live world's
    /// events, for every scenario in the catalogue.
    #[test]
    fn round_trip_monitor_findings_match_direct_run() {
        for &id in ScenarioId::all() {
            let mut scenario = ocr_scenario::build(id);
            scenario.run_headline();
            let events = scenario.world.events();

            let mut direct = Monitor::new();
            direct.observe_all(events);

            let mut buf = Vec::new();
            write_events(events, &mut buf).unwrap();
            let replayed_events = read_events(&buf[..]).unwrap();
            let mut replayed = Monitor::new();
            replayed.observe_all(&replayed_events);

            assert_eq!(
                finding_kinds(&direct),
                finding_kinds(&replayed),
                "{id:?}: replayed capture raised different findings than the live run"
            );
        }
    }
}
