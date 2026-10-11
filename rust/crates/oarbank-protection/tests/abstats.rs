//! The harness statistics (D52): shared vectors with the coordinator's Python twin, and property checks of the
//! decision rule (a zero-effect plant rarely yields "slowdown"; a 5 % effect is detected).

use std::path::PathBuf;

use oarbank_protection::abstats::{self, Decision, SplitMix};
use serde_json::Value;

fn vectors() -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../src/oarbank/contracts/vectors/abstats-vectors.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn close(a: f64, b: f64, what: &str) {
    assert!((a - b).abs() <= 1e-9 * (1.0 + b.abs()), "{what}: rust {a} python {b}");
}

#[test]
fn the_shared_vectors_agree_with_python() {
    let v = vectors();
    let mut rng = SplitMix(42);
    for x in v["splitmix_42"].as_array().unwrap() {
        assert_eq!(rng.next(), x.as_u64().unwrap());
    }
    for q in v["t_quantile"].as_array().unwrap() {
        let (p, df, want) = (q[0].as_f64().unwrap(), q[1].as_f64().unwrap(), q[2].as_f64().unwrap());
        close(abstats::t_quantile(p, df), want, &format!("t_quantile({p}, {df})"));
    }
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let xs: Vec<f64> = c["log_ratios"].as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect();
        let margin = c["margin"].as_f64().unwrap();
        let a = abstats::analyse(&xs, margin, c["seed"].as_u64().unwrap());
        let w = &c["analysis"];
        assert_eq!(a.decision.as_str(), w["decision"].as_str().unwrap(), "{name}");
        assert_eq!(a.reason, w["reason"].as_str().unwrap(), "{name}");
        assert_eq!(a.further_blocks, w["further_blocks"].as_u64(), "{name}");
        for (k, got) in [("mean", a.mean), ("sd", a.sd), ("r", a.r), ("r_lo", a.r_lo), ("r_hi", a.r_hi),
                         ("t_lo", a.t_lo), ("t_hi", a.t_hi)] {
            match w[k].as_f64() {
                Some(want) => close(got, want, &format!("{name} {k}")),
                None => assert!(got.is_infinite(), "{name} {k}"),
            }
        }
        let seq = abstats::sequential(&xs, margin).map(|d| d.as_str().to_string());
        assert_eq!(seq.as_deref(), c["sequential"].as_str(), "{name} sequential");
        close(abstats::min_detectable(abstats::sd(&xs), 12), c["min_detectable_12"].as_f64().unwrap(), name);
        if let Some(b) = c["blocks_needed"].as_u64() {
            assert_eq!(abstats::blocks_needed(abstats::sd(&xs), margin), b, "{name}");
        }
    }
}

/// Normal-ish noise from splitmix (the sum of four uniforms, centred and scaled to unit variance).
fn noise(rng: &mut SplitMix) -> f64 {
    let u: f64 = (0..4).map(|_| rng.next() as f64 / u64::MAX as f64).sum();
    (u - 2.0) * (3.0f64).sqrt()
}

/// A zero-effect plant never yields "slowdown" more often than the test's error rate (5 % one-sided), over many
/// seeds; and a 5 % slowdown at a typical spread is detected with at least the stated power (80 %).
#[test]
fn the_decision_keeps_its_error_rates() {
    let (runs, blocks, spread, margin) = (400, 12, 0.02, 0.02);
    let mut rng = SplitMix(7);
    let mut false_slowdown = 0;
    let mut detected = 0;
    for seed in 0..runs {
        let zero: Vec<f64> = (0..blocks).map(|_| spread * noise(&mut rng)).collect();
        if abstats::analyse(&zero, margin, seed).decision == Decision::Slowdown {
            false_slowdown += 1;
        }
        let five: Vec<f64> = (0..blocks).map(|_| (0.95f64).ln() + spread * noise(&mut rng)).collect();
        if abstats::analyse(&five, margin, seed).decision == Decision::Slowdown {
            detected += 1;
        }
    }
    let alpha = false_slowdown as f64 / runs as f64;
    let power = detected as f64 / runs as f64;
    eprintln!("zero effect: slowdown in {:.1} % of runs; 5 % effect: detected in {:.1} %", alpha * 100.0, power * 100.0);
    assert!(alpha <= 0.05, "false slowdowns {alpha}");
    assert!(power >= 0.8, "power {power}");
}

/// The sequential test never stops a zero-effect run as "slowdown" more often than its error rate, looking after
/// every block (always-valid inference).
#[test]
fn the_sequential_test_is_always_valid() {
    let (runs, blocks, spread, margin) = (400, 30, 0.02, 0.02);
    let mut rng = SplitMix(11);
    let mut stopped_wrong = 0;
    for _ in 0..runs {
        let mut xs = vec![];
        for _ in 0..blocks {
            xs.push(spread * noise(&mut rng));
            if abstats::sequential(&xs, margin) == Some(Decision::Slowdown) {
                stopped_wrong += 1;
                break;
            }
        }
    }
    let rate = stopped_wrong as f64 / runs as f64;
    eprintln!("zero effect: sequential slowdown stops in {:.1} % of runs", rate * 100.0);
    assert!(rate <= 0.05, "{rate}");
}

#[test]
fn power_planning() {
    // a spread of 2 % between blocks needs 7 blocks for an 80 % chance at a 2 % margin
    assert_eq!(abstats::blocks_needed(0.02, 0.02), 7);
    assert!(abstats::min_detectable(0.02, 7) < 0.02);
    assert!(abstats::min_detectable(0.02, 4) > 0.024);
    assert_eq!(abstats::blocks_needed(0.0, 0.02), 2);
}
