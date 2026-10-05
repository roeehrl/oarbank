#!/usr/bin/env python3
"""Turn a hardware report (an issue opened with .github/ISSUE_TEMPLATE/hardware-report.yml) into a draft row for the
compatibility table, vendor/oarbank-sdk/docs/compatibility/reports.json, and check it with the SDK's own checks.

    uv run python scripts/compat-row.py 42                 # reads the issue with `gh issue view`
    uv run python scripts/compat-row.py --json issue.json  # the saved output of `gh issue view 42 --json body,author,url,createdAt`

The row goes to stdout, the problems the SDK's checks find to stderr (exit status 1 then). A draft is not a verdict:
the maintainer checks the status against the output and writes `notes` before adding it (the SDK's
docs/compatibility/README.md). Reports posted as plain comments on the help-wanted issues have no fields to read, and
are written up by hand."""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = "roeehrl/oarbank"
SDK = Path(__file__).resolve().parents[1] / "vendor" / "oarbank-sdk"
NO_RESPONSE = "_No response_"

# Each form field's label, and what each of its options means in a row.
FAMILY = ("Operating system", {"macOS": "darwin", "Linux": "linux", "Windows": "windows"})
ARCH = ("Architecture", {"arm64 (Apple silicon, ARM64, aarch64)": "arm64", "amd64 (x86_64, x64, Intel Mac)": "amd64"})
MACHINE = ("Machine", {"Physical machine": "physical", "Virtual machine": "vm", "CI runner": "ci"})
VENDOR = ("GPU vendor", {"NVIDIA": "nvidia", "AMD": "amd", "Intel": "intel", "Apple": "apple",
                         "Virtual GPU (a hypervisor's display adapter)": "virtual", "No GPU": "none"})
RAN_IN = ("Where it ran", {"On the host": "host", "In a Linux container (Podman, Docker or Colima)": "container",
                           "In WSL containers (Windows)": "wslc"})
STATUS = ("Did it work?", {"Yes: everything I ran worked": "verified", "Partly: something failed, or an API is wrong": "partial",
                           "No: it failed": "not-working"})
RESULT = {"Not run": None, "Passed": "passed", "Failed": "failed", "Skipped itself": "skipped"}
TEST = "Test: "                                       # a test's dropdown is labelled "Test: <id from reports.json>"
OS_VERSION, KERNEL, MODEL, DRIVER = "OS name and version", "Kernel", "GPU model", "GPU driver version"
TOOLS, COMMIT, GPU_APIS, NOTES, REDACTION = "Tool versions", "Oarbank commit", "GPU APIs", "What was wrong or missing", "Redaction"


def sdk_checks():
    """The SDK's gen_compatibility module: its schema, its checks and its list of tests."""
    spec = importlib.util.spec_from_file_location("gen_compatibility", SDK / "scripts" / "gen_compatibility.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sections(body: str) -> dict[str, str]:
    """An issue form's body: `### <label>` headings, each followed by its value (None where the field was left empty)."""
    out, label, lines = {}, None, []
    for line in body.replace("\r\n", "\n").split("\n"):
        if line.startswith("### "):
            if label is not None:
                out[label] = "\n".join(lines).strip()
            label, lines = line[4:].strip(), []
        elif label is not None:
            lines.append(line)
    if label is not None:
        out[label] = "\n".join(lines).strip()
    return {k: (None if v in ("", NO_RESPONSE) else v) for k, v in out.items()}


def unfence(text: str | None) -> str | None:
    if text is None:
        return None
    m = re.fullmatch(r"```[a-z]*\n(.*?)\n?```", text.strip(), re.DOTALL)
    return m.group(1) if m else text


def checked(text: str | None) -> list[str]:
    return re.findall(r"^- \[[xX]\] (.+)$", text or "", re.MULTILINE)


def one_line(text: str) -> str:
    """Row text is one line without `|` (a table cell)."""
    return " ".join(text.replace("|", "/").split())


def slug(*parts: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", " ".join(parts).lower()).strip("-")


def draft(issue: dict, tests: dict) -> tuple[dict, list[str]]:
    """The row an issue's fields give, and what could not be read from them."""
    f, problems = sections(issue["body"]), []

    def pick(field):
        label, options = field
        value = f.get(label)
        if value not in options:
            problems.append(f"{label!r}: {value!r} is none of the form's options")
        return options.get(value)

    if not checked(f.get(REDACTION)):
        problems.append("the reporter did not confirm the redaction")
    platform = f"{pick(FAMILY)}-{pick(ARCH)}"
    vendor = pick(VENDOR)
    model, driver = f.get(MODEL), f.get(DRIVER)
    if vendor == "none":
        model = driver = None
    tools = {}
    for line in (unfence(f.get(TOOLS)) or "").splitlines():
        name, sep, version = line.partition(":") if ":" in line else line.strip().rpartition(" ")
        if line.strip() and not (sep and name.strip() and version.strip()):
            problems.append(f"{TOOLS!r}: cannot read {line!r} as `name: version`")
        elif line.strip():
            tools[name.strip()] = one_line(version)
    apis = {"host": None, "containers": None}
    try:
        reported = json.loads(unfence(f.get(GPU_APIS)) or "null")
        reported = reported.get("gpu_apis", reported) if isinstance(reported, dict) else {}
        apis = {k: reported.get(k) for k in apis}
    except json.JSONDecodeError as e:
        problems.append(f"{GPU_APIS!r}: not JSON ({e})")
    ran = checked(f.get(RAN_IN[0]))
    unknown = [r for r in ran if r not in RAN_IN[1]]
    problems += [f"{RAN_IN[0]!r}: {r!r} is none of the form's options" for r in unknown]
    results = []
    for tid in sorted(tests):
        value = f.get(TEST + tid)
        if value is not None and value not in RESULT:
            problems.append(f"{TEST + tid!r}: {value!r} is none of the form's options")
        elif RESULT.get(value):
            results.append({"id": tid, "result": RESULT[value]})
    os_ = one_line(f.get(OS_VERSION) or "")
    row = {
        "id": slug(model or "no-gpu", os_, platform.split("-")[1]),
        "status": pick(STATUS),
        "platform": platform,
        "os": os_,
        **({"kernel": one_line(f[KERNEL])} if f.get(KERNEL) else {}),
        "machine": pick(MACHINE),
        "gpu": {"vendor": vendor, "model": model and one_line(model), "driver": driver and one_line(driver)},
        "ran_in": [RAN_IN[1][r] for r in ran if r in RAN_IN[1]],
        "tools": tools,
        "gpu_apis": apis,
        "tests": results,
        "commit": (f.get(COMMIT) or "").strip().lower(),
        "date": issue["createdAt"][:10],
        "source": {"kind": "issue", "url": issue["url"], "reporter": issue["author"]["login"]},
        **({"notes": one_line(f[NOTES])} if f.get(NOTES) else {}),
    }
    return row, problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("issue", nargs="?", help="the report's issue number on " + REPO)
    src.add_argument("--json", type=Path, help="the saved output of gh issue view N --json body,author,url,createdAt")
    a = ap.parse_args(argv)
    if a.json:
        issue = json.loads(a.json.read_text(encoding="utf-8"))
    else:
        issue = json.loads(subprocess.run(["gh", "issue", "view", a.issue, "--repo", REPO, "--json", "body,author,url,createdAt"],
                                          check=True, capture_output=True, text=True).stdout)
    gen = sdk_checks()
    data = gen.load()
    row, problems = draft(issue, data["tests"])
    problems += gen.problems({**data, "reports": [*data["reports"], row]})
    print(json.dumps(row, indent=2, ensure_ascii=False))
    if problems:
        print("problems:", *problems, sep="\n  ", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
