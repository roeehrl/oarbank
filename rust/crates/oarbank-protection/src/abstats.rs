//! The statistics of the paired on/off harness (D52; docs/design/gpu-cotenancy.md). Pure functions, duplicated in
//! the coordinator's Python (`oarbank.contracts.abstats`) and held equal by shared vectors
//! (`src/oarbank/contracts/vectors/abstats-vectors.json`), as the protection matcher is.
//!
//! Each block holds one ON and one OFF window; its statistic is the log ratio `ln(on / off)` of the protected
//! process's mean progress rate in the two windows. The mean log ratio gets a 90 % interval two ways: a bootstrap
//! over blocks (the blocks are the resampled units, so the autocorrelation of step times within a window never
//! matters) and a t interval. The decision is a one-sided equivalence test (TOST) at the owner's margin Δ: "no
//! slowdown shown" when the lower bound of `R = exp(mean)` is above `1 − Δ`, "slowdown" when the whole interval is
//! below 1 and the point estimate below `1 − Δ`, otherwise "inconclusive". The two intervals must agree; when they
//! do not (few blocks, a skewed sample), the result is inconclusive.

use serde::{Deserialize, Serialize};

/// One-sided 95 % (the bounds of a two-sided 90 % interval) and 80 % power quantiles of the standard normal.
pub const Z95: f64 = 1.6448536269514722;
pub const Z80: f64 = 0.8416212335729143;
/// Bootstrap resamples.
pub const RESAMPLES: usize = 2000;
/// The always-valid test's error rate (each direction).
pub const SEQ_ALPHA: f64 = 0.05;

/// splitmix64: the bootstrap's generator, the same in Rust and Python so the shared vectors agree exactly.
#[derive(Debug, Clone)]
pub struct SplitMix(pub u64);

impl SplitMix {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform index below `n` (`n` > 0).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// A fair coin.
    pub fn coin(&mut self) -> bool {
        self.next() >> 63 == 1
    }
}

pub fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

/// The sample standard deviation (n − 1); 0 for fewer than two values.
pub fn sd(xs: &[f64]) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let m = mean(xs);
    (xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (xs.len() - 1) as f64).sqrt()
}

/// The linear-interpolation quantile of sorted values (type 7).
pub fn quantile(sorted: &[f64], q: f64) -> f64 {
    let h = (sorted.len() - 1) as f64 * q;
    let lo = h.floor() as usize;
    let hi = (lo + 1).min(sorted.len() - 1);
    sorted[lo] + (h - lo as f64) * (sorted[hi] - sorted[lo])
}

/// ln Γ(x) (Lanczos, g = 7).
fn ln_gamma(x: f64) -> f64 {
    const C: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        return (std::f64::consts::PI / (std::f64::consts::PI * x).sin()).ln() - ln_gamma(1.0 - x);
    }
    let x = x - 1.0;
    let mut a = C[0];
    let t = x + 7.5;
    for (i, c) in C.iter().enumerate().skip(1) {
        a += c / (x + i as f64);
    }
    0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
}

/// The continued fraction of the regularized incomplete beta function (modified Lentz).
fn beta_cf(a: f64, b: f64, x: f64) -> f64 {
    let (qab, qap, qam) = (a + b, a + 1.0, a - 1.0);
    let tiny = 1e-300;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < tiny {
        d = tiny;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..300 {
        let m = m as f64;
        let m2 = 2.0 * m;
        let aa = m * (b - m) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < tiny {
            d = tiny;
        }
        c = 1.0 + aa / c;
        if c.abs() < tiny {
            c = tiny;
        }
        d = 1.0 / d;
        h *= d * c;
        let aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < tiny {
            d = tiny;
        }
        c = 1.0 + aa / c;
        if c.abs() < tiny {
            c = tiny;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < 1e-15 {
            break;
        }
    }
    h
}

/// The regularized incomplete beta function I_x(a, b).
fn inc_beta(a: f64, b: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let bt = (ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b) + a * x.ln() + b * (1.0 - x).ln()).exp();
    if x < (a + 1.0) / (a + b + 2.0) {
        bt * beta_cf(a, b, x) / a
    } else {
        1.0 - bt * beta_cf(b, a, 1.0 - x) / b
    }
}

/// The Student t distribution's CDF.
pub fn t_cdf(t: f64, df: f64) -> f64 {
    let x = df / (df + t * t);
    let tail = 0.5 * inc_beta(df / 2.0, 0.5, x);
    if t >= 0.0 {
        1.0 - tail
    } else {
        tail
    }
}

/// The Student t quantile (bisection on the CDF; `p` in (0, 1)).
pub fn t_quantile(p: f64, df: f64) -> f64 {
    let (mut lo, mut hi) = (-1e3, 1e3);
    for _ in 0..200 {
        let mid = 0.5 * (lo + hi);
        if t_cdf(mid, df) < p {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    0.5 * (lo + hi)
}

/// The percentile bootstrap 90 % interval of the mean.
pub fn bootstrap_interval(xs: &[f64], seed: u64, resamples: usize) -> (f64, f64) {
    let n = xs.len();
    let mut rng = SplitMix(seed);
    let mut means: Vec<f64> = (0..resamples)
        .map(|_| (0..n).map(|_| xs[rng.below(n)]).sum::<f64>() / n as f64)
        .collect();
    means.sort_by(|a, b| a.total_cmp(b));
    (quantile(&means, 0.05), quantile(&means, 0.95))
}

/// The t 90 % interval of the mean.
pub fn t_interval(xs: &[f64]) -> (f64, f64) {
    let n = xs.len() as f64;
    let m = mean(xs);
    let half = t_quantile(0.95, n - 1.0) * sd(xs) / n.sqrt();
    (m - half, m + half)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    NoSlowdown,
    Slowdown,
    Inconclusive,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoSlowdown => "no_slowdown",
            Self::Slowdown => "slowdown",
            Self::Inconclusive => "inconclusive",
        }
    }
}

/// The TOST decision of one interval of the mean log ratio at margin Δ.
pub fn decide(lo: f64, hi: f64, m: f64, margin: f64) -> Decision {
    let l = (1.0 - margin).ln();
    if lo > l {
        Decision::NoSlowdown
    } else if hi < 0.0 && m < l {
        Decision::Slowdown
    } else {
        Decision::Inconclusive
    }
}

/// The analysis of a run's blocks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Analysis {
    pub n: usize,
    /// The mean log ratio and its standard deviation over blocks.
    pub mean: f64,
    pub sd: f64,
    /// `R = exp(mean)`, its bootstrap interval and its t interval (ratio scale).
    pub r: f64,
    pub r_lo: f64,
    pub r_hi: f64,
    pub t_lo: f64,
    pub t_hi: f64,
    pub margin: f64,
    pub decision: Decision,
    /// Why, in words.
    pub reason: String,
    /// More blocks the observed variance says "no slowdown shown" would need (None: it cannot be shown at this
    /// effect).
    pub further_blocks: Option<u64>,
}

/// Analyse the per-block log ratios at margin Δ (`seed` drives the bootstrap).
pub fn analyse(log_ratios: &[f64], margin: f64, seed: u64) -> Analysis {
    let n = log_ratios.len();
    let l = (1.0 - margin).ln();
    if n < 2 {
        let m = log_ratios.first().copied().unwrap_or(0.0);
        return Analysis {
            n,
            mean: m,
            sd: 0.0,
            r: m.exp(),
            r_lo: 0.0,
            r_hi: f64::INFINITY,
            t_lo: 0.0,
            t_hi: f64::INFINITY,
            margin,
            decision: Decision::Inconclusive,
            reason: "fewer than two blocks".into(),
            further_blocks: None,
        };
    }
    let (m, s) = (mean(log_ratios), sd(log_ratios));
    let (bl, bh) = bootstrap_interval(log_ratios, seed, RESAMPLES);
    let (tl, th) = t_interval(log_ratios);
    let (db, dt) = (decide(bl, bh, m, margin), decide(tl, th, m, margin));
    let (decision, reason) = if db == dt {
        let why = match db {
            Decision::NoSlowdown => "the lower bound of the 90 % interval is above 1 − margin",
            Decision::Slowdown => "the whole 90 % interval is below 1 and the estimate below 1 − margin",
            Decision::Inconclusive => "the 90 % interval reaches below 1 − margin",
        };
        (db, why.to_string())
    } else {
        (Decision::Inconclusive, format!("the bootstrap says {} and the t interval {}", db.as_str(), dt.as_str()))
    };
    let further_blocks = if m > l {
        let need = if s > 0.0 { ((Z95 * s / (m - l)).powi(2)).ceil() as u64 } else { 2 };
        Some(need.saturating_sub(n as u64))
    } else {
        None
    };
    Analysis {
        n,
        mean: m,
        sd: s,
        r: m.exp(),
        r_lo: bl.exp(),
        r_hi: bh.exp(),
        t_lo: tl.exp(),
        t_hi: th.exp(),
        margin,
        decision,
        reason,
        further_blocks: if decision == Decision::NoSlowdown { Some(0) } else { further_blocks },
    }
}

/// The smallest slowdown (ratio scale, 0.03 = 3 %) a run of `blocks` blocks detects with 80 % power at a
/// between-block standard deviation `sd` of the log ratio.
pub fn min_detectable(sd: f64, blocks: u32) -> f64 {
    let d = (Z95 + Z80) * sd / (blocks.max(1) as f64).sqrt();
    1.0 - (-d).exp()
}

/// The blocks needed to show "no slowdown" at margin Δ with 80 % power when the true effect is none.
pub fn blocks_needed(sd: f64, margin: f64) -> u64 {
    let l = -(1.0 - margin).ln();
    (((Z95 + Z80) * sd / l).powi(2)).ceil().max(2.0) as u64
}

/// The always-valid sequential test (mixture SPRT, normal approximation with the observed variance and a normal
/// mixing distribution of scale Δ): the logarithm of the likelihood ratio against θ0. Stop when it reaches ln(1 / α).
pub fn msprt(xs: &[f64], theta0: f64, margin: f64) -> f64 {
    let n = xs.len() as f64;
    let s2 = sd(xs).powi(2).max(1e-12);
    let tau2 = (1.0 - margin).ln().powi(2).max(1e-12);
    let m = mean(xs);
    0.5 * (s2 / (s2 + n * tau2)).ln() + n * n * tau2 * (m - theta0).powi(2) / (2.0 * s2 * (s2 + n * tau2))
}

/// The sequential decision after a block (None: keep going). Needs at least three blocks.
pub fn sequential(xs: &[f64], margin: f64) -> Option<Decision> {
    if xs.len() < 3 {
        return None;
    }
    let l = (1.0 - margin).ln();
    let m = mean(xs);
    if m < l && msprt(xs, 0.0, margin) >= (1.0 / SEQ_ALPHA).ln() {
        return Some(Decision::Slowdown);
    }
    if m > l && msprt(xs, l, margin) >= (1.0 / SEQ_ALPHA).ln() {
        return Some(Decision::NoSlowdown);
    }
    None
}
