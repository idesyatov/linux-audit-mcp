//! Per-host anomaly detection over stored health history (Stage B2).
//!
//! A real anomaly is a deviation from *this host's own* recent norm, not a
//! crossing of a global threshold. We build a **robust** baseline for each
//! metric - the median and the median absolute deviation (MAD) over the recent
//! history window - and flag the current reading when it is both statistically
//! far from the median *and* materially large. Robust statistics matter here:
//! one transient spike must not inflate the norm and mask later readings, which
//! is exactly what a mean/standard-deviation baseline would do.
//!
//! Deliberately informational: an anomaly signals an unusual workload, not a
//! hardening regression, so it never feeds the security score, the health
//! `overall` status, or the exit code.
//!
//! Architecture: this module is pure (no I/O, no config/run dependency) and owns
//! [`AnomalyConfig`], which `config.rs` imports - mirroring how `health` owns
//! `Thresholds`. The run orchestration reads history and resolves the per-target
//! config, then calls [`detect`]; see [`crate::run::annotate_anomalies`].

use serde::Deserialize;

use crate::health::{Anomaly, HealthReport};
use crate::history::Snapshot;

/// Guards divide-by-zero and treats near-flat history as flat.
const EPS: f64 = 1e-9;

/// Consistency constant making `1.4826 * MAD` a stddev-equivalent scale for
/// normally distributed data (so the threshold `k` reads like a z-score).
const MAD_TO_SIGMA: f64 = 1.4826;

/// Per-target anomaly-detection settings. Every field has a sensible default; a
/// target may override any subset via `[targets.x.anomaly]` (inherited from a
/// group the same way `health` thresholds are).
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnomalyConfig {
    /// Master switch for this target.
    pub enabled: bool,
    /// Modified z-score threshold: flag when deviation ≥ `k` scaled-MADs.
    /// 3.5 is the Iglewicz-Hoaglin default.
    pub k: f64,
    /// Materiality floor: the change must also be at least this fraction of the
    /// baseline (e.g. 0.15 = 15%). Suppresses trivial deviations on very stable
    /// metrics, where MAD is ~0 and any wobble would otherwise look infinite.
    pub rel_floor: f64,
    /// Minimum history samples before a metric is judged (avoids false alarms on
    /// a young baseline).
    pub min_samples: usize,
    /// How many most-recent snapshots form the baseline window.
    pub window: usize,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            k: 3.5,
            rel_floor: 0.15,
            min_samples: 8,
            window: 100,
        }
    }
}

/// A metric's robust baseline over a set of readings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Baseline {
    pub median: f64,
    /// Median absolute deviation (raw, unscaled).
    pub mad: f64,
    pub n: usize,
}

/// Median of a slice (`0.0` for empty). Does not mutate the input.
fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut s: Vec<f64> = values.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = s.len();
    if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    }
}

/// Median + MAD for one metric's readings.
pub fn baseline_of(values: &[f64]) -> Baseline {
    let med = median(values);
    let devs: Vec<f64> = values.iter().map(|v| (v - med).abs()).collect();
    Baseline {
        median: med,
        mad: median(&devs),
        n: values.len(),
    }
}

/// Detect anomalies in `report` against `history` (the baseline window, newest
/// snapshots). Pure: the caller supplies the already-windowed history and the
/// resolved config. Returns one [`Anomaly`] per metric that clears both gates.
///
/// A metric is anomalous when:
///   1. it has at least `min_samples` historical readings,
///   2. its modified z-score `|x - median| / (1.4826 * MAD) ≥ k`, and
///   3. the change is material: `|x - median| ≥ rel_floor * (|median| + eps)`.
///
/// Gate 3 is what makes a flat history safe: when MAD ≈ 0 the z-score is treated
/// as large, so materiality alone decides, and a 21%→22% disk blip stays quiet.
pub fn detect(report: &HealthReport, history: &[Snapshot], cfg: &AnomalyConfig) -> Vec<Anomaly> {
    if !cfg.enabled {
        return Vec::new();
    }
    let mut out = Vec::new();
    for m in &report.metrics {
        let Some(current) = m.numeric else { continue };
        // This metric's readings across the window, in history order.
        let series: Vec<f64> = history
            .iter()
            .filter_map(|s| s.metrics.get(m.id).copied())
            .collect();
        if series.len() < cfg.min_samples {
            continue;
        }
        let b = baseline_of(&series);
        let dev = (current - b.median).abs();
        let scaled_mad = MAD_TO_SIGMA * b.mad;
        let z = if scaled_mad > EPS {
            dev / scaled_mad
        } else if dev > EPS {
            f64::INFINITY // flat history: let the materiality gate decide
        } else {
            0.0
        };
        let material = dev >= cfg.rel_floor * (b.median.abs() + EPS);
        if z >= cfg.k && material {
            out.push(Anomaly {
                metric_id: m.id.to_string(),
                current,
                median: b.median,
                pct_change: (current - b.median) / (b.median.abs() + EPS) * 100.0,
                z,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::{HealthStatus, Metric};
    use std::collections::BTreeMap;

    fn metric(id: &'static str, value: f64) -> Metric {
        Metric {
            id,
            title: id,
            status: HealthStatus::Ok,
            value: String::new(),
            detail: String::new(),
            numeric: Some(value),
        }
    }

    fn report(metrics: Vec<Metric>) -> HealthReport {
        HealthReport {
            metrics,
            top_cpu: Vec::new(),
            top_mem: Vec::new(),
            overall: HealthStatus::Ok,
            anomalies: Vec::new(),
            anomaly_note: None,
        }
    }

    /// History of `n` snapshots each holding `id -> value`.
    fn history(id: &str, values: &[f64]) -> Vec<Snapshot> {
        values
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let mut m = BTreeMap::new();
                m.insert(id.to_string(), *v);
                Snapshot {
                    ts: i as u64,
                    overall: HealthStatus::Ok,
                    metrics: m,
                }
            })
            .collect()
    }

    #[test]
    fn median_odd_and_even() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&[1.0, 2.0, 3.0, 4.0]), 2.5);
        assert_eq!(median(&[]), 0.0);
    }

    #[test]
    fn baseline_median_and_mad() {
        // values 1..=9: median 5; |dev| = {4,3,2,1,0,1,2,3,4}; median of that = 2.
        let b = baseline_of(&[1., 2., 3., 4., 5., 6., 7., 8., 9.]);
        assert_eq!(b.median, 5.0);
        assert_eq!(b.mad, 2.0);
        assert_eq!(b.n, 9);
    }

    #[test]
    fn spike_over_stable_history_is_flagged() {
        // 12 readings around 0.30, current 2.50 -> clear anomaly.
        let hist = history("health-load", &[0.30; 12]);
        let r = report(vec![metric("health-load", 2.50)]);
        let a = detect(&r, &hist, &AnomalyConfig::default());
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].metric_id, "health-load");
        assert!(a[0].pct_change > 100.0);
    }

    #[test]
    fn value_within_noisy_range_is_not_flagged() {
        let hist = history(
            "health-load",
            &[0.2, 0.4, 0.3, 0.5, 0.1, 0.35, 0.25, 0.45, 0.3, 0.4],
        );
        let r = report(vec![metric("health-load", 0.38)]); // ordinary
        assert!(detect(&r, &hist, &AnomalyConfig::default()).is_empty());
    }

    #[test]
    fn flat_history_small_change_is_immaterial() {
        // disk pinned at 21%: MAD 0. 22% is only ~5% > baseline < 15% floor -> quiet.
        let hist = history("health-disk", &[21.0; 10]);
        let small = report(vec![metric("health-disk", 22.0)]);
        assert!(detect(&small, &hist, &AnomalyConfig::default()).is_empty());
        // 30% is +43% > floor and z is infinite -> flagged.
        let big = report(vec![metric("health-disk", 30.0)]);
        assert_eq!(detect(&big, &hist, &AnomalyConfig::default()).len(), 1);
    }

    #[test]
    fn short_history_is_skipped() {
        let hist = history("health-load", &[0.3; 5]); // < min_samples (8)
        let r = report(vec![metric("health-load", 9.0)]);
        assert!(detect(&r, &hist, &AnomalyConfig::default()).is_empty());
    }

    #[test]
    fn disabled_detects_nothing() {
        let hist = history("health-load", &[0.3; 20]);
        let r = report(vec![metric("health-load", 9.0)]);
        let cfg = AnomalyConfig {
            enabled: false,
            ..AnomalyConfig::default()
        };
        assert!(detect(&r, &hist, &cfg).is_empty());
    }

    #[test]
    fn metric_absent_from_history_is_skipped() {
        // current has net-throughput, history only has load -> no series, no panic.
        let hist = history("health-load", &[0.3; 12]);
        let r = report(vec![metric("health-net-throughput", 500.0)]);
        assert!(detect(&r, &hist, &AnomalyConfig::default()).is_empty());
    }

    #[test]
    fn config_parses_and_rejects_unknown_fields() {
        let cfg: AnomalyConfig = toml::from_str("k = 4.0\nmin_samples = 12").unwrap();
        assert_eq!(cfg.k, 4.0);
        assert_eq!(cfg.min_samples, 12);
        assert!(cfg.enabled); // default preserved
        assert!(toml::from_str::<AnomalyConfig>("bogus = 1").is_err());
    }
}
