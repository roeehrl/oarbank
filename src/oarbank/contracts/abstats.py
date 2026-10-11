"""The statistics of the paired on/off harness (D52; docs/design/gpu-cotenancy.md).

The agent's `oarbank-protection` crate (`abstats.rs`) decides a run on the node; this twin lets the coordinator
re-check a run's blocks, render the same numbers and test the decision rules. The two are held equal by shared
vectors (`vectors/abstats-vectors.json`, generated from this module by `vectors/gen_abstats.py`).

Each block holds one ON and one OFF window; its statistic is ln(on / off) of the protected process's mean progress
rate. The mean log ratio gets a 90 % interval by a bootstrap over blocks (splitmix64, 2000 resamples, type-7
quantiles) and by a t interval; the decision is a one-sided equivalence test at the owner's margin, and the two
intervals must agree (else "inconclusive").
"""
import math

Z95 = 1.6448536269514722
Z80 = 0.8416212335729143
RESAMPLES = 2000
SEQ_ALPHA = 0.05
_MASK = (1 << 64) - 1


class SplitMix:
    """splitmix64, bit-for-bit the agent's."""

    def __init__(self, seed: int):
        self.state = seed & _MASK

    def next(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & _MASK
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK
        return z ^ (z >> 31)

    def below(self, n: int) -> int:
        return self.next() % n

    def coin(self) -> bool:
        return self.next() >> 63 == 1


def mean(xs) -> float:
    return sum(xs) / len(xs)


def sd(xs) -> float:
    if len(xs) < 2:
        return 0.0
    m = mean(xs)
    return math.sqrt(sum((x - m) * (x - m) for x in xs) / (len(xs) - 1))


def quantile(sorted_xs, q: float) -> float:
    h = (len(sorted_xs) - 1) * q
    lo = math.floor(h)
    hi = min(lo + 1, len(sorted_xs) - 1)
    return sorted_xs[lo] + (h - lo) * (sorted_xs[hi] - sorted_xs[lo])


_LANCZOS = (0.9999999999998099, 676.5203681218851, -1259.1392167224028, 771.3234287776531, -176.6150291621406,
            12.507343278686905, -0.13857109526572012, 9.984369578019572e-6, 1.5056327351493116e-7)


def _ln_gamma(x: float) -> float:
    if x < 0.5:
        return math.log(math.pi / math.sin(math.pi * x)) - _ln_gamma(1.0 - x)
    x -= 1.0
    a = _LANCZOS[0]
    t = x + 7.5
    for i in range(1, 9):
        a += _LANCZOS[i] / (x + i)
    return 0.5 * math.log(2 * math.pi) + (x + 0.5) * math.log(t) - t + math.log(a)


def _beta_cf(a: float, b: float, x: float) -> float:
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    tiny = 1e-300
    c, d = 1.0, 1.0 - qab * x / qap
    d = tiny if abs(d) < tiny else d
    d = 1.0 / d
    h = d
    for m in range(1, 300):
        m2 = 2.0 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = tiny if abs(d) < tiny else d
        c = 1.0 + aa / c
        c = tiny if abs(c) < tiny else c
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = tiny if abs(d) < tiny else d
        c = 1.0 + aa / c
        c = tiny if abs(c) < tiny else c
        d = 1.0 / d
        dl = d * c
        h *= dl
        if abs(dl - 1.0) < 1e-15:
            break
    return h


def _inc_beta(a: float, b: float, x: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    bt = math.exp(_ln_gamma(a + b) - _ln_gamma(a) - _ln_gamma(b) + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _beta_cf(a, b, x) / a
    return 1.0 - bt * _beta_cf(b, a, 1.0 - x) / b


def t_cdf(t: float, df: float) -> float:
    tail = 0.5 * _inc_beta(df / 2.0, 0.5, df / (df + t * t))
    return 1.0 - tail if t >= 0 else tail


def t_quantile(p: float, df: float) -> float:
    lo, hi = -1e3, 1e3
    for _ in range(200):
        mid = 0.5 * (lo + hi)
        if t_cdf(mid, df) < p:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def bootstrap_interval(xs, seed: int, resamples: int = RESAMPLES) -> tuple[float, float]:
    n = len(xs)
    rng = SplitMix(seed)
    means = []
    for _ in range(resamples):
        s = 0.0
        for _ in range(n):
            s += xs[rng.below(n)]
        means.append(s / n)
    means.sort()
    return quantile(means, 0.05), quantile(means, 0.95)


def t_interval(xs) -> tuple[float, float]:
    n = len(xs)
    m = mean(xs)
    half = t_quantile(0.95, n - 1.0) * sd(xs) / math.sqrt(n)
    return m - half, m + half


def decide(lo: float, hi: float, m: float, margin: float) -> str:
    l = math.log(1.0 - margin)
    if lo > l:
        return "no_slowdown"
    if hi < 0.0 and m < l:
        return "slowdown"
    return "inconclusive"


def analyse(log_ratios, margin: float, seed: int) -> dict:
    """The agent's Analysis, field for field."""
    n = len(log_ratios)
    l = math.log(1.0 - margin)
    if n < 2:
        m = log_ratios[0] if log_ratios else 0.0
        return {"n": n, "mean": m, "sd": 0.0, "r": math.exp(m), "r_lo": 0.0, "r_hi": math.inf, "t_lo": 0.0,
                "t_hi": math.inf, "margin": margin, "decision": "inconclusive", "reason": "fewer than two blocks",
                "further_blocks": None}
    m, s = mean(log_ratios), sd(log_ratios)
    bl, bh = bootstrap_interval(log_ratios, seed)
    tl, th = t_interval(log_ratios)
    db, dt = decide(bl, bh, m, margin), decide(tl, th, m, margin)
    if db == dt:
        decision = db
        reason = {"no_slowdown": "the lower bound of the 90 % interval is above 1 − margin",
                  "slowdown": "the whole 90 % interval is below 1 and the estimate below 1 − margin",
                  "inconclusive": "the 90 % interval reaches below 1 − margin"}[db]
    else:
        decision, reason = "inconclusive", f"the bootstrap says {db} and the t interval {dt}"
    further = None
    if m > l:
        need = math.ceil((Z95 * s / (m - l)) ** 2) if s > 0 else 2
        further = max(0, need - n)
    return {"n": n, "mean": m, "sd": s, "r": math.exp(m), "r_lo": math.exp(bl), "r_hi": math.exp(bh),
            "t_lo": math.exp(tl), "t_hi": math.exp(th), "margin": margin, "decision": decision, "reason": reason,
            "further_blocks": 0 if decision == "no_slowdown" else further}


def min_detectable(s: float, blocks: int) -> float:
    d = (Z95 + Z80) * s / math.sqrt(max(blocks, 1))
    return 1.0 - math.exp(-d)


def blocks_needed(s: float, margin: float) -> int:
    l = -math.log(1.0 - margin)
    return int(max(2.0, math.ceil(((Z95 + Z80) * s / l) ** 2)))


def msprt(xs, theta0: float, margin: float) -> float:
    """The mixture likelihood ratio against theta0, as its logarithm (it overflows otherwise)."""
    n = len(xs)
    s2 = max(sd(xs) ** 2, 1e-12)
    tau2 = max(math.log(1.0 - margin) ** 2, 1e-12)
    m = mean(xs)
    return 0.5 * math.log(s2 / (s2 + n * tau2)) + n * n * tau2 * (m - theta0) ** 2 / (2.0 * s2 * (s2 + n * tau2))


def sequential(xs, margin: float) -> str | None:
    if len(xs) < 3:
        return None
    l = math.log(1.0 - margin)
    m = mean(xs)
    if m < l and msprt(xs, 0.0, margin) >= math.log(1.0 / SEQ_ALPHA):
        return "slowdown"
    if m > l and msprt(xs, l, margin) >= math.log(1.0 / SEQ_ALPHA):
        return "no_slowdown"
    return None


def describe(analysis: dict) -> str:
    """The decision in words, as the console and the CLI print it."""
    a = analysis
    if not a or a.get("n", 0) < 2:
        return "Not enough blocks to decide."
    pct = lambda x: f"{x * 100:.1f} %"
    interval = f"90 % interval {pct(a['r_lo'])}–{pct(a['r_hi'])}"
    margin = f"{a['margin'] * 100:.0f} %"
    d = a["decision"]
    if d == "no_slowdown":
        return (f"No slowdown shown: the protected process ran at {pct(a['r'])} of its speed without fleet work "
                f"({interval}), within the {margin} margin.")
    if d == "slowdown":
        return (f"Slowdown: the protected process ran at {pct(a['r'])} of its speed without fleet work ({interval}), "
                f"more than the {margin} margin.")
    more = a.get("further_blocks")
    tail = f" About {more} more blocks would decide it." if more else ""
    return (f"Inconclusive: {pct(a['r'])} of its speed without fleet work ({interval}); the interval reaches below "
            f"the {margin} margin.{tail}")
