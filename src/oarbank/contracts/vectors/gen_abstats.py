"""Generate abstats-vectors.json: the harness statistics (oarbank.contracts.abstats) over fixed samples; the agent's
`abstats.rs` must give the same answers (tests/abstats.rs in oarbank-protection).

    (from the repository root) uv run --extra dev python src/oarbank/contracts/vectors/gen_abstats.py
"""
import json
import math
from pathlib import Path

from oarbank.contracts import abstats as A

OUT = Path(__file__).parent / "abstats-vectors.json"


def sample(seed: int, n: int, effect: float, spread: float) -> list[float]:
    """Deterministic log ratios: effect plus spread times a centred uniform from splitmix64."""
    rng = A.SplitMix(seed)
    return [round(effect + spread * ((rng.next() / 2**64) - 0.5) * 2, 12) for _ in range(n)]


def main():
    rng = A.SplitMix(42)
    cases = []
    for name, seed, n, effect, spread, margin in [
        ("no effect, tight", 1, 12, 0.0, 0.004, 0.02),
        ("no effect, noisy", 2, 12, 0.0, 0.05, 0.02),
        ("five percent slowdown", 3, 12, math.log(0.95), 0.01, 0.02),
        ("one percent slowdown", 4, 16, math.log(0.99), 0.003, 0.02),
        ("two blocks", 5, 2, 0.0, 0.01, 0.02),
        ("one block", 6, 1, 0.0, 0.01, 0.02),
        ("speed-up", 7, 8, math.log(1.03), 0.01, 0.05),
        ("skewed", 8, 4, -0.001, 0.03, 0.02),
        ("near the margin", 9, 10, math.log(0.98), 0.04, 0.02),
    ]:
        xs = sample(seed, n, effect, spread)
        a = A.analyse(xs, margin, seed)
        cases.append({"name": name, "log_ratios": xs, "margin": margin, "seed": seed,
                      "analysis": {k: (None if isinstance(v, float) and math.isinf(v) else v) for k, v in a.items()},
                      "sequential": A.sequential(xs, margin),
                      "min_detectable_12": A.min_detectable(A.sd(xs), 12),
                      "blocks_needed": A.blocks_needed(A.sd(xs), margin) if len(xs) > 1 else None})
    doc = {"splitmix_42": [rng.next() for _ in range(5)],
           "t_quantile": [[p, df, A.t_quantile(p, df)] for p, df in [(0.95, 1), (0.95, 2), (0.95, 5), (0.95, 11),
                                                                      (0.95, 30), (0.975, 10), (0.9, 3)]],
           "cases": cases}
    OUT.write_text(json.dumps(doc, indent=1) + "\n")


if __name__ == "__main__":
    main()
