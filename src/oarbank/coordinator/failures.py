"""A job's failure as its runner declared it (runner protocol, "Exit codes"; failure.json `{reason, detail, fault?,
retryable?}`), as the agent reports it to /v1/attempts/<id>/fail, and the record the coordinator keeps on the job
(jobs.failure_json) for its views, explain and the module's campaign.tick / host.jobs.query."""
import json
import re

from oarbank_sdk import runner_protocol as rp

from .db import jl

# job faults the agent attributes itself (an OOM kill, a process outside the sandbox), not a runner's failure.json: they
# keep the stage's retry, since the runner never declared that the job can never succeed
AGENT_JOB_FAULTS = {"oom", "sandbox_escape"}
FAILURE_DETAIL_MAX = 4096       # failure.json `detail`, as the agent truncates it (runner protocol)
TICK_FAILURE_DETAIL = 512       # characters of a failure's detail a campaign.tick or host.jobs.query row carries
MODULE_REASON = re.compile(r"^[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_.-]*$")
# how every agent heads the stderr tail of a failure: `"<failure.json reason>": <detail as JSON>`
_TAIL_HEAD = re.compile(r'^"([A-Za-z0-9_./-]{1,80})": (.*)$')


def failure_summary(f: dict | None) -> str:
    """One line for a job's failure record: its code (the module's own, or the end reason) and detail."""
    if not f:
        return ""
    head = f.get("code") or f.get("reason") or "failed"
    return head + (f": {f['detail']}" if f.get("detail") else "")


def failure_view(raw, detail_max: int | None = None) -> dict | None:
    """A job's stored failure record as views and modules see it (detail cut to `detail_max` characters)."""
    f = jl(raw) if isinstance(raw, (str, bytes)) or raw is None else raw
    if not f:
        return None
    out = {k: f.get(k) for k in ("reason", "code", "detail", "fault", "retryable", "final", "attempt_id", "node_id", "at")}
    if detail_max is not None and out["detail"] and len(out["detail"]) > detail_max:
        out["detail"] = out["detail"][:detail_max] + "…"
    return out


def declared_failure(body: dict) -> tuple[str | None, str]:
    """The runner's failure.json `reason` and `detail` as the agent reported them: its `failure` object, or, from an
    agent that predates it, the head of `stderr_tail` (`"<reason>": <detail as JSON>`, how every agent starts it)."""
    f = body.get("failure")
    if isinstance(f, dict):
        code, detail = f.get("reason"), f.get("detail")
    else:
        code, detail = None, None
        m = _TAIL_HEAD.match((body.get("stderr_tail") or "").split("\n", 1)[0])
        if m:
            code = m.group(1)
            try:
                detail = json.loads(m.group(2))
            except ValueError:
                detail = m.group(2)
    code = code if isinstance(code, str) and (MODULE_REASON.match(code) or code in rp.FAILURE_REASONS) else None
    if detail is not None and not isinstance(detail, str):
        detail = json.dumps(detail)
    return code, (detail or "")[:FAILURE_DETAIL_MAX]


def declared_retryable(body: dict) -> bool | None:
    """failure.json `retryable` as the agent reported it (top level, or inside `failure`); None when not declared."""
    r = body.get("retryable")
    if r is None and isinstance(body.get("failure"), dict):
        r = body["failure"].get("retryable")
    return r if isinstance(r, bool) else None


def failure_breakdown(r, campaign_id: str) -> list[dict]:
    """Why a campaign's jobs failed (`oarbank campaign show`, the console's campaign page): each failure code (the
    runner's own `<module-short>/<code>`, or the end reason) and final state, with its job count, its latest job and
    that job's detail."""
    rows = r.q("SELECT state, COALESCE(json_extract(failure_json,'$.code'), json_extract(failure_json,'$.reason')) code, "
               "COUNT(*) n, MAX(job_id) job_id FROM jobs WHERE campaign_id=? AND state IN ('failed','quarantined') "
               "AND failure_json IS NOT NULL GROUP BY state, code ORDER BY n DESC, code LIMIT 20", (campaign_id,))
    out = []
    for f in rows:
        d = r.one("SELECT json_extract(failure_json,'$.detail') d FROM jobs WHERE job_id=?", (f["job_id"],))
        out.append({"state": f["state"], "code": f["code"], "jobs": f["n"], "job_id": f["job_id"],
                    "detail": ((d or {}).get("d") or "")[:TICK_FAILURE_DETAIL]})
    return out
