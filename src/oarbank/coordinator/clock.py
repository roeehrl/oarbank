"""The coordinator's single time source.

* Production: wall time anchored at process start plus *monotonic* elapsed time, so a wall-clock
  step (NTP correction, manual change) after startup can never mass-expire leases.
* Tests / simulation: `set_fake(t)` / `advance(dt)` make time fully deterministic.
Every oarbankd module must read time through `now()` — never `time.time()` directly.
"""
import time

_BASE_WALL = time.time()
_BASE_MONO = time.monotonic()
_fake: float | None = None


def now() -> float:
    if _fake is not None:
        return _fake
    return _BASE_WALL + (time.monotonic() - _BASE_MONO)


def set_fake(t: float | None):
    global _fake
    _fake = t


def advance(dt: float):
    global _fake
    if _fake is None:
        _fake = now()
    _fake += dt
