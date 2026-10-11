"""An owner-run measurement of macOS's private PRIO_DARWIN_GPU switch (docs/design/gpu-cotenancy.md, "An owner-run
experiment"). Oarbank does not use it: this script answers whether it is worth offering one day, as an opt-in last
resort for GPU work that cannot hold a duty.

    python3 bench/prio_darwin_gpu.py --seconds 20 --i-understand -- <command that runs GPU work>

It starts the command itself and acts on nothing else: the command's process group is the only target, so a
protected program can never be touched. Three phases of `--seconds` each: the work runs; the work is denied the GPU
(`setpriority(PRIO_DARWIN_GPU, pid, PRIO_DARWIN_GPU_DENY)` on every process of its group); the work is allowed again.
For each phase it reports whether the call was permitted, the group's GPU time growth (the AGX driver's per-process
counters, as the agent reads them) and whether the work is still alive. At the end it allows the GPU again and stops
the command. Run it in a window you free for it, against fleet work you choose (an llmserve job on MLX, a Metal
benchmark), never against a protected program.

The constants are xnu's (bsd/sys/resource.h): PRIO_DARWIN_GPU 5, ALLOW 1, DENY 2. Private and undocumented: they may
change or stop working in any macOS release, and that is part of what the measurement shows.
"""
import argparse
import ctypes
import json
import os
import re
import signal
import subprocess
import sys
import time

PRIO_DARWIN_GPU = 5
PRIO_DARWIN_GPU_ALLOW = 0x1
PRIO_DARWIN_GPU_DENY = 0x2


def gpu_ns_by_pid() -> dict[int, float] | None:
    """Each process's accumulated GPU time (ns) from the AGX driver's user clients (None where unreadable)."""
    try:
        out = subprocess.run(["ioreg", "-r", "-c", "AGXDeviceUserClient", "-d", "1", "-l"], capture_output=True, text=True,
                             timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    got: dict[int, float] = {}
    for entry in out.split("+-o ")[1:]:
        m = re.search(r'"IOUserClientCreator" = "pid (\d+),', entry)
        if m:
            pid = int(m.group(1))
            got[pid] = got.get(pid, 0.0) + sum(float(x) for x in re.findall(r'"accumulatedGPUTime"=(\d+)', entry))
    return got


def group_pids(pgid: int) -> list[int]:
    ps = subprocess.run(["ps", "-A", "-o", "pid=,pgid=,stat="], capture_output=True, text=True).stdout
    return [int(f[0]) for f in (line.split() for line in ps.splitlines())
            if len(f) == 3 and int(f[1]) == pgid and not f[2].startswith("Z")]


def set_gpu(pids: list[int], value: int) -> dict[int, str]:
    """setpriority(PRIO_DARWIN_GPU) on each pid; per pid "ok" or the error."""
    libc = ctypes.CDLL(None, use_errno=True)
    out = {}
    for pid in pids:
        r = libc.setpriority(PRIO_DARWIN_GPU, ctypes.c_uint(pid), ctypes.c_int(value))
        out[pid] = "ok" if r == 0 else os.strerror(ctypes.get_errno())
    return out


def measure(pgid: int, seconds: float) -> dict:
    pids = group_pids(pgid)
    a = gpu_ns_by_pid()
    t = time.monotonic()
    time.sleep(seconds)
    b = gpu_ns_by_pid()
    span = time.monotonic() - t
    pids = sorted(set(pids) | set(group_pids(pgid)))
    busy = None if a is None or b is None else sum(max(0.0, b.get(p, 0.0) - a.get(p, 0.0)) for p in pids) / 1e9 / span
    return {"gpu_busy": None if busy is None else round(busy, 4), "alive": bool(group_pids(pgid)), "pids": pids}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seconds", type=float, default=20.0, help="length of each phase")
    ap.add_argument("--i-understand", action="store_true",
                    help="confirm: a private macOS interface, run by hand, on work this script starts, never a protected program")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="-- then the command that runs GPU work")
    a = ap.parse_args(argv)
    cmd = a.command[1:] if a.command[:1] == ["--"] else a.command
    if sys.platform != "darwin":
        print("PRIO_DARWIN_GPU is a macOS switch; nothing to measure here", file=sys.stderr)
        return 2
    if not a.i_understand or not cmd:
        ap.print_usage(sys.stderr)
        print("needs --i-understand and a command after --", file=sys.stderr)
        return 2
    child = subprocess.Popen(cmd, start_new_session=True)       # its own group: the only thing this script touches
    report = {"command": cmd, "phases": []}
    try:
        time.sleep(min(5.0, a.seconds))                          # let it start its GPU work
        report["phases"].append({"phase": "running", **measure(child.pid, a.seconds)})
        denied = set_gpu(group_pids(child.pid), PRIO_DARWIN_GPU_DENY)
        report["phases"].append({"phase": "denied", "setpriority": denied, **measure(child.pid, a.seconds)})
        allowed = set_gpu(group_pids(child.pid), PRIO_DARWIN_GPU_ALLOW)
        report["phases"].append({"phase": "allowed again", "setpriority": allowed, **measure(child.pid, a.seconds)})
    finally:
        set_gpu(group_pids(child.pid), PRIO_DARWIN_GPU_ALLOW)
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(10)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
    report["exit"] = child.returncode
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
