"""The hardware report form (.github/ISSUE_TEMPLATE/hardware-report.yml), scripts/compat-row.py and the SDK's
compatibility table (vendor/oarbank-sdk/docs/compatibility/) agree: every row field has a form field, every gated test
the table knows has a dropdown giving its exact command, and a report becomes a row the SDK's checks accept."""
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FORM = ROOT / ".github" / "ISSUE_TEMPLATE" / "hardware-report.yml"
SCRIPT = ROOT / "scripts" / "compat-row.py"

_spec = importlib.util.spec_from_file_location("compat_row", SCRIPT)
cr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cr)
GEN = cr.sdk_checks()
TESTS = GEN.load()["tests"]


def _scalar(text: str) -> str:
    text = text.strip()
    return json.loads(text) if text.startswith('"') else text      # the form's double-quoted strings use JSON's escapes


def form_fields() -> list[dict]:
    """The form's body elements: type, id, label, description and options. The form keeps to a plain block style, so
    a line reader is enough."""
    fields = []
    for line in FORM.read_text(encoding="utf-8").splitlines():
        if m := re.fullmatch(r"  - type: (\w+)", line):
            fields.append({"type": m[1], "options": []})
        elif m := re.fullmatch(r"    id: (\w+)", line):
            fields[-1]["id"] = m[1]
        elif m := re.fullmatch(r"      (label|description): (.+)", line):
            fields[-1][m[1]] = _scalar(m[2])
        elif m := re.fullmatch(r"        - (?:label: )?(.+)", line):
            fields[-1]["options"].append(_scalar(m[1]))
    return [f for f in fields if f["type"] != "markdown"]


def by_label() -> dict[str, dict]:
    return {f["label"]: f for f in form_fields()}


def render_body(values: dict[str, str]) -> str:
    """An issue body as GitHub writes it from a submitted form: every field's label as a heading, then its value."""
    out = []
    for f in form_fields():
        v = values.get(f["label"])
        if f["type"] == "checkboxes":
            v = "\n".join(f"- [{'X' if o in (v or []) else ' '}] {o}" for o in f["options"])
        elif f["type"] == "textarea" and v and (lang := {"GPU APIs": "json", "Full output": "text"}.get(f["label"])):
            v = f"```{lang}\n{v}\n```"
        out.append(f"### {f['label']}\n\n{v or cr.NO_RESPONSE}")
    return "\n\n".join(out)


NVIDIA_LINUX = {
    "Operating system": "Linux",
    "Architecture": "amd64 (x86_64, x64, Intel Mac)",
    "OS name and version": "Ubuntu 24.04 LTS",
    "Kernel": "6.8.0-85-generic",
    "Machine": "Physical machine",
    "GPU vendor": "NVIDIA",
    "GPU model": "GeForce RTX 4070",
    "GPU driver version": "580.82.07",
    "Where it ran": ["On the host", "In a Linux container (Podman, Docker or Colima)"],
    "Tool versions": "Podman: 5.6.1 (rootless)\nNVIDIA Container Toolkit: 1.18.0",
    "Oarbank commit": "1dc15f7",
    "GPU APIs": json.dumps({"host": ["cuda", "opencl", "vulkan"], "containers": ["cuda"],
                            "evidence": {"cuda": "NVIDIA GeForce RTX 4070"}, "platform": "linux-amd64"}),
    "Test: test_gpu_apis": "Passed",
    "Test: doctor_probe_gpu": "Passed",
    "Test: doctor_probe_service": "Not run",
    "Test: verify_windows_containers": "Not run",
    "Test: verify_windows_containers_gpu": "Not run",
    "Test: live_colima_gpu": "Not run",
    "Did it work?": "Yes: everything I ran worked",
    "Full output": "doctor: ok",
    "Redaction": ["I removed host names, user names, paths, serial numbers and addresses from everything above."],
}
ISSUE = {"url": "https://github.com/roeehrl/oarbank/issues/42", "author": {"login": "a-reporter"}, "createdAt": "2026-10-01T09:00:00Z"}


def issue(**change) -> dict:
    return {**ISSUE, "body": render_body({**NVIDIA_LINUX, **change})}


def test_a_report_becomes_a_row_the_sdk_accepts():
    row, problems = cr.draft(issue(), TESTS)
    assert problems == []
    assert row == {
        "id": "geforce-rtx-4070-ubuntu-24-04-lts-amd64",
        "status": "verified",
        "platform": "linux-amd64",
        "os": "Ubuntu 24.04 LTS",
        "kernel": "6.8.0-85-generic",
        "machine": "physical",
        "gpu": {"vendor": "nvidia", "model": "GeForce RTX 4070", "driver": "580.82.07"},
        "ran_in": ["host", "container"],
        "tools": {"Podman": "5.6.1 (rootless)", "NVIDIA Container Toolkit": "1.18.0"},
        "gpu_apis": {"host": ["cuda", "opencl", "vulkan"], "containers": ["cuda"]},
        "tests": [{"id": "doctor_probe_gpu", "result": "passed"}, {"id": "test_gpu_apis", "result": "passed"}],
        "commit": "1dc15f7",
        "date": "2026-10-01",
        "source": {"kind": "issue", "url": ISSUE["url"], "reporter": "a-reporter"},
    }
    data = GEN.load()
    assert GEN.problems({**data, "reports": [*data["reports"], row]}) == []


def test_the_script_prints_the_row_from_a_saved_issue(tmp_path):
    saved = tmp_path / "issue.json"
    saved.write_text(json.dumps(issue(**{"What was wrong or missing": "Nothing | all good"})), encoding="utf-8")
    out = subprocess.run([sys.executable, str(SCRIPT), "--json", str(saved)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["notes"] == "Nothing / all good"


def test_a_machine_without_a_gpu_has_no_model_or_driver():
    row, problems = cr.draft(issue(**{"GPU vendor": "No GPU", "GPU APIs": '{"host": [], "containers": []}'}), TESTS)
    assert problems == [] and row["gpu"] == {"vendor": "none", "model": None, "driver": None}
    assert row["id"].startswith("no-gpu-")


@pytest.mark.parametrize("change, problem", [
    ({"Redaction": []}, "did not confirm the redaction"),
    ({"GPU APIs": "host: cuda"}, "not JSON"),
    ({"Tool versions": "podman"}, "cannot read 'podman'"),
    ({"Machine": "Laptop"}, "'Laptop' is none of the form's options"),
])
def test_what_cannot_be_read_is_reported(change, problem):
    _, problems = cr.draft(issue(**change), TESTS)
    assert any(problem in p for p in problems), problems


def test_every_dropdown_and_checkbox_option_means_something_in_a_row():
    fields = by_label()
    for label, options in (cr.FAMILY, cr.ARCH, cr.MACHINE, cr.VENDOR, cr.STATUS):
        assert fields[label]["type"] == "dropdown" and fields[label]["options"] == list(options), label
    assert fields[cr.RAN_IN[0]]["type"] == "checkboxes" and fields[cr.RAN_IN[0]]["options"] == list(cr.RAN_IN[1])
    for label in (cr.OS_VERSION, cr.KERNEL, cr.MODEL, cr.DRIVER, cr.COMMIT, cr.TOOLS, cr.GPU_APIS, cr.NOTES, cr.REDACTION):
        assert label in fields, label


def test_every_gated_test_in_the_table_has_a_dropdown_with_its_command():
    tests = {f["label"][len(cr.TEST):]: f for f in form_fields() if f["label"].startswith(cr.TEST)}
    assert sorted(tests) == sorted(TESTS)
    for tid, f in tests.items():
        assert f["type"] == "dropdown" and f["id"] == tid and f["options"] == list(cr.RESULT)
        assert f"`{TESTS[tid]['command']}`" in f["description"], tid
