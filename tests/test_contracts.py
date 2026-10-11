"""The core's contracts (oarbank.contracts): the operation registry covers every mutation, reason codes cover every end
reason written, and the explain, audit and protection models hold their rules."""
import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from helpers import make_db
from oarbank.coordinator import app as coord_app
from oarbank.contracts import explain, operations as ops, protection as prot
from oarbank.contracts import reason_codes as rc, schemas

SRC = Path(__file__).parents[1] / "src" / "oarbank"
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def mutating_routes(app):
    return {(m, r.path) for r in app.routes if hasattr(r, "methods") for m in r.methods & MUTATING}


@pytest.fixture(scope="module")
def routes(tmp_path_factory):
    from oarbank.console.app import console_app
    from oarbank.console.state import ConsoleState
    path = tmp_path_factory.mktemp("db") / "oarbank.sqlite3"
    db = make_db(path)
    return {"agent": mutating_routes(coord_app.agent_app(db)),
            "gui": mutating_routes(coord_app.admin_app(db)),
            "console": mutating_routes(console_app(ConsoleState(path, "http://127.0.0.1:1")))}


# ------------------------------------------------------------------ operation registry

def test_every_mutating_route_is_an_operation_or_agent_protocol(routes):
    """No mutation exists outside the registry."""
    missing = sorted(r for r in routes["agent"] | routes["gui"]
                     if r not in ops.AGENT_ROUTES | ops.SESSION_ROUTES and not ops.operations_for(*r))
    assert not missing, f"unregistered mutations: {missing}"


def test_agent_routes_are_the_agent_listener(routes):
    assert ops.AGENT_ROUTES == routes["agent"]


def test_no_operation_points_at_a_missing_route(routes):
    stale = [(op.id, "api", r.method, r.path) for op in ops.OPS for r in op.routes
             if (r.method, r.path) not in routes["gui"]]
    stale += [(op.id, "console", r.method, r.path) for op in ops.OPS for r in op.gui
              if (r.method, r.path) not in routes["console"]]
    assert not stale


def test_console_mutations_are_only_operation_forwards(routes):
    """oarbank-console has no write path of its own: its mutating routes forward operations, proxy /api, or stage a
    browser upload's bytes for datasets.register or an upload operation (forwarded to oarbankd, which changes nothing
    until the operation)."""
    allowed = {("POST", ops.CONSOLE_ROUTE_PATH), ("POST", "/apply/{op}"), ("POST", ops.CONSOLE_STAGE_PATH),
               ("POST", "/api/{path:path}"), ("PUT", "/api/{path:path}"), ("PATCH", "/api/{path:path}"),
               ("DELETE", "/api/{path:path}")} | {(r.method, r.path) for r in ops.CONSOLE_UPLOADS}
    assert routes["console"] <= allowed | ops.CONSOLE_SESSION_ROUTES


def test_shared_routes_are_fully_discriminated():
    """A route that serves several operations names, for each, the field value that selects it."""
    by_route = {}
    for op in ops.OPS:
        for r in (*op.routes, *op.gui):
            by_route.setdefault((r.method, r.path), []).append((op.id, r.when))
    for route, entries in by_route.items():
        if len(entries) > 1:
            whens = [w for _, w in entries]
            assert all(whens) and len({json.dumps(w, sort_keys=True) for w in whens}) == len(whens), route


def test_console_forms_match_the_registry():
    """Every operation a console template renders is registered with the console route, and vice versa."""
    rendered = set()
    for t in (SRC / "console" / "templates").glob("*.html"):
        rendered |= set(re.findall(r'op_form\("([a-z_.]+)"', t.read_text(encoding="utf-8")))
    registered = {op.id for op in ops.OPS if op.gui and not op.id.startswith("mod.")}   # module ops render in module pages
    assert rendered == registered


def test_console_templates_have_no_inline_script_or_handlers():
    for t in (SRC / "console" / "templates").glob("*.html"):
        text = t.read_text(encoding="utf-8")
        assert not re.search(r"<script(?![^>]*\bsrc=)", text), t.name
        assert not re.search(r"\son[a-z]+\s*=", text), t.name
        assert "javascript:" not in text, t.name
        # host-rendered fragments only: the shared fleet fragment and module pages/panels from the published renderer
        allowed_safe = {"fleet.html": 1, "module_page.html": 1, "job.html": 1, "node.html": 1, "_campaign_body.html": 1}
        assert text.count("| safe") + text.count("|safe") <= allowed_safe.get(t.name, 0), t.name


def test_cli_mutates_only_through_registered_operations():
    src = (SRC / "cli" / "main.py").read_text(encoding="utf-8")
    assert not re.findall(r'api\("(POST|PUT|PATCH|DELETE)"', src)            # every write is an operation (run_op)
    named = re.findall(r'run_op\("([a-z_.]+)"', src) + re.findall(r'"(nodes\.[a-z_]+)"', src)
    assert named and all(o in ops.REGISTRY for o in named), [o for o in named if o not in ops.REGISTRY]
    posts = re.findall(r'http_request\("POST", f"\{URL\}([^"]+)"', src)     # the op endpoint and the upload routes
    routes = {r.path for op in ops.OPS for r in op.routes if r.method == "POST"}
    assert posts and all(p in routes for p in posts), posts


def test_registry_rules():
    for op in ops.OPS:
        if op.reverses:
            assert op.reverses in ops.REGISTRY, op.id
        assert op.reason_policy == ("required" if op.tier in ("T2", "T3") else op.reason or ops.DEFAULT_REASON[op.tier])
    assert ops.REGISTRY["fleet.pause"].tier == "T0" and ops.REGISTRY["fleet.resume"].reason_policy == "required"
    with pytest.raises(ValidationError, match="preview"):
        ops.Operation(id="x.y", area="jobs", summary="s", tier="T2", category="modify", idempotency="natural",
                      routes=[ops.R("POST", "/x")])


def test_bulk_moves_up_one_tier():
    retry = ops.REGISTRY["jobs.retry"]
    assert ops.effective_tier(retry, items=3) == "T0"
    assert ops.effective_tier(retry, items=11) == "T1"
    assert ops.effective_tier(ops.REGISTRY["jobs.cancel"], fleet_fraction=0.5) == "T2"


# ------------------------------------------------------------------ reason codes

# every attempt end reason (and result reason) oarbankd and the agent write (rust/crates/oarbank-agent, oarbank-protection)
END_REASONS = ["ok", "exit_nonzero", "bad_input", "doctor", "transient", "timeout", "lease_expired", "agent_restart", "agent_stop",
               "release_invalid", "stale_generation", "lost_race", "module_revoked", "module_disabled", "node_quarantined",
               "node_retired", "dispute_party", "fleet_halt", "golden_failed", "superseded", "oom", "preempt_memory",
               "preempt_protection", "limit_cpu", "limit_mem", "limit_schedule", "user_cancel", "input_invalidated", "placement_rebound",
               "job_cancelled", "job_quarantined", "attempt_closed", "job_done", "no_metrics", "bad_artifact",
               "artifact_missing", "input_missing", "input_mismatch", "mode_mismatch", "golden_mismatch", "disputed",
               "self_inconsistent"]


@pytest.mark.parametrize("s", END_REASONS)
def test_every_end_reason_has_a_code(s):
    assert rc.WIRE[s] in rc.REGISTRY


def test_non_failure_releases_are_end_reasons():
    from oarbank.coordinator import core
    assert core.NON_FAILURE_RELEASES <= set(END_REASONS)


def test_remedies_name_registered_operations():
    for c in rc.CODES:
        for op in c.remedies:
            assert op in ops.REGISTRY, (c.code, op)


def test_attempt_end_codes_declare_attribution():
    for c in rc.CODES:
        if c.category in ("attempt_end", "verdict"):
            assert c.counts_against_node is not None and c.counts_against_job is not None, c.code


ROOT = SRC.parents[1]
# code files that produce reason codes and end reasons: the core and the agent (with its protection crate)
PRODUCERS = [p for p in (*SRC.rglob("*.py"), *SRC.rglob("*.html"), *ROOT.glob("rust/crates/*/src/**/*.rs"))
             if p != SRC / "contracts" / "reason_codes.py" and "__pycache__" not in p.parts]
# where the console and explain name codes: the explain document, the predicates and exclusions it runs, the Verify
# conditions and the console's node conditions name nothing but codes in capitals; the rest of the console also holds
# HTTP verbs, tiers and environment variables
CODE_ONLY = [SRC / "console" / "views.py",
             *(SRC / "coordinator" / f for f in ("explain.py", "predicates.py", "platforms.py", "invariants.py"))]
CONSUMERS = [*(SRC / "console").rglob("*.py"), *(SRC / "console" / "templates").glob("*.html"), SRC / "console" / "static" / "app.js",
             SRC / "coordinator" / "modsandbox.py", *CODE_ONLY]
CODE = r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*"
ANY_CODE = re.compile(rf"""["']({CODE})["'](?!\s*:)""")
# elsewhere a code is a quoted literal with an underscore that is neither a dict key nor an environment variable, or any
# quoted literal passed as `code=`, `"code":` or `"reason":`, compared with a reason, or given as a predicate's code
CODE_LITERAL = re.compile(r"""(?<!environ\.get\()(?<!getenv\()["']([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)["'](?!\s*:)""")
CODE_POSITION = re.compile(rf"""(?:\bcode=|["'](?:code|reason)["']\s*:\s*|\[["']reason["']\]\s*==\s*|\bR\([^,()]+,\s*)["']({CODE})["']""")


def _quoted(texts, s):
    return any(f'"{s}"' in t or f"'{s}'" in t for t in texts)


def test_every_code_has_a_producer():
    """No code is registered that nothing emits: each is named as a literal (or written as one of its end reasons) by
    the core or the agent. The agent formats some codes from a prefix (`format!("RUNG_{}", rung)`)."""
    texts = [p.read_text(encoding="utf-8") for p in PRODUCERS]
    prefixes = {m for t in texts for m in re.findall(r'"([A-Z][A-Z0-9]*_)\{\}"', t)}
    orphans = [c.code for c in rc.CODES
               if not _quoted(texts, c.code) and not any(_quoted(texts, w) for w in c.wire)
               and not any(c.code.startswith(p) and re.fullmatch(r"[A-Z0-9]+", c.code[len(p):]) for p in prefixes)]
    assert not orphans, f"reason codes nothing produces: {orphans}"


def test_console_and_explain_name_only_registered_codes():
    named = {}
    for p in CONSUMERS:
        t = p.read_text(encoding="utf-8")
        for m in (*CODE_LITERAL.finditer(t), *CODE_POSITION.finditer(t), *(ANY_CODE.finditer(t) if p in CODE_ONLY else ())):
            named.setdefault(m.group(1), p.name)
    unknown = {c: f for c, f in named.items() if c not in rc.REGISTRY}
    assert not unknown, f"codes the console or explain use that the registry lacks: {unknown}"


def test_agent_protection_reasons_are_registered():
    """Every reason the agent's protection layer journals is a code (a formatted `PREFIX_{}` names a code family)."""
    calls = [re.compile(rf'journal(?:_record)?\(\s*(?:"[a-z_]+"|[a-z_&.]+),\s*(?:&format!\()?"({CODE}(?:_\{{\}})?)"'),
             re.compile(rf'ProtectionEvent::new\(\s*"[a-z_]+",\s*.+?,\s*"({CODE})"', re.S)]
    reasons = {(p.name, m.group(1)) for p in ROOT.glob("rust/crates/oarbank-protection/src/**/*.rs") for c in calls
               for m in c.finditer(p.read_text(encoding="utf-8"))}
    assert len(reasons) >= 10, reasons
    unknown = [(f, s) for f, s in sorted(reasons)
               if not (any(c.startswith(s[:-2]) for c in rc.REGISTRY) if s.endswith("_{}") else s in rc.REGISTRY)]
    assert not unknown, f"protection reasons the agent journals that the registry lacks: {unknown}"


def test_core_end_reasons_are_registered():
    """Every end reason oarbankd writes as a literal maps to a code (the agent's are pinned in END_REASONS)."""
    pats = [r'_end_attempt\([^()]*?,\s*"[a-z]+",\s*"([a-z_]+)"', r"end_reason='([a-z_]+)'", r'reason, accepted = "([a-z_]+)"',
            r'accepted, reason = 0, "([a-z_]+)"', r' reason = "([a-z_]+)"', r'stage_problem = "([a-z_]+)"',
            r'release\(db, node, attempt_id, "([a-z_]+)"\)', r'_cancel_goldens\([^()]*,\s*"([a-z_]+)"\)']
    found = set()
    for f in ("core.py", "ops.py"):
        t = (SRC / "coordinator" / f).read_text(encoding="utf-8")
        for pat in pats:
            found |= set(re.findall(pat, t))
        for mapping in re.findall(r"reason, accepted = \{([^}]*)\}", t):      # {state: end reason}[state]
            found |= set(re.findall(r':\s*"([a-z_]+)"', mapping))
    artifacts = (SRC / "coordinator" / "core.py").read_text(encoding="utf-8").split("def _register_artifacts", 1)[1].split("\ndef ", 1)[0]
    found |= set(re.findall(r'return "([a-z_]+)"', artifacts))                 # its rejection reasons
    assert {"node_quarantined", "node_retired", "job_cancelled", "stale_generation", "bad_artifact", "golden_failed"} <= found
    missing = sorted(r for r in found if r not in rc.WIRE)
    assert not missing, f"end reasons without a code: {missing}"


def test_render_is_plain_text():
    assert rc.REGISTRY["POOL_EXHAUSTED"].render(pool="scorer", free=0, need=1) == \
        "No free scorer token (0 free, 1 needed)"


# ------------------------------------------------------------------ explain

def test_explain_example_from_the_design():
    doc = explain.ExplainDocument.model_validate({
        "subject": {"kind": "job", "id": 812},
        "as_of": {"snapshot_version": 48213, "evaluated_at": 1790000000.0},
        "verdict": "pending", "headline": {"code": "NO_ELIGIBLE_NODE", "text": "No node can run this job right now"},
        "summary": [{"code": "NODE_PAUSED_BY_ADMIN", "nodes": ["laptop"], "evidence": [991201]},
                    {"code": "POOL_EXHAUSTED", "nodes": ["mini-1", "mini-2"], "detail": {"pool": "scorer", "free": 0, "need": 1}}],
        "clauses": [{"predicate": "pool(scorer) >= 1", "matched": 2, "of": 5}],
        "matrix": [{"node": "mini-1", "results": [{"predicate": "pool(scorer) >= 1", "code": "POOL_EXHAUSTED",
                                                   "outcome": "fail", "observed": 0, "required": 1, "layer": "placement"}]}],
        "remedies": [{"op": "jobs.set_priority", "params": {"job_id": 812}, "label": "Raise priority"}],
    })
    for row in doc.summary:
        assert row.code in rc.REGISTRY
    for r in doc.remedies:
        assert r.op in ops.REGISTRY


# ------------------------------------------------------------------ protection

EXAMPLE = SRC / "contracts" / "fixtures" / "protection-example.toml"


def test_protection_example_loads():
    c = prot.load(EXAMPLE)
    assert c.node.mode == "moderate" and len(c.rules) == 7
    trainer = c.rules[0]
    assert trainer.reserve.cpu is None and trainer.reserve.mem_gb == "peak(300s).footprint + 2"   # never a CPU yield for it
    assert trainer.during[0].cap_fleet.staging_mbps == 0
    games = next(r for r in c.rules if r.id == "games")
    assert games.active_when.gpu_active.min_busy == 0.10 and games.active_when.for_s == 10
    assert prot.ActiveWhen.model_validate({"gpu_active": {}}).gpu_active.min_busy == 0.05


def test_new_nodes_default_to_moderate():
    assert prot.ProtectionConfig().node.mode == "moderate" == prot.DEFAULT_MODE


@pytest.mark.parametrize("rule,match", [
    ({"id": "a", "match": {"team_id": "EQHXZ8M8AV"}}, "at least one action"),
    ({"id": "a", "match": {"team_id": "EQHXZ8M8AV"}, "ignore": True, "cap_fleet": {"slots": 1}}, "ignore"),
    ({"id": "a", "match": {"bundle_id": "x"}, "tree": "same_team", "cap_fleet": {"slots": 1}}, "same_team"),
    ({"id": "a", "match": {}, "cap_fleet": {"slots": 1}}, "at least one key"),
    ({"id": "a", "match": {"name": "x"}, "reserve": {"cpu": "rm -rf /"}}, "reservation"),
    ({"id": "a", "match": {"name": "x"}, "protect": {"metric": "progress_rate", "max_slowdown": 0.1}}, "source"),
    ({"id": "a", "match": {"name": "x"}, "protect": {"metric": "cpu_stall"}}, "exactly one"),
    ({"id": "a", "match": {"name": "x"}, "cap_fleet": {"slots": 1}, "kill_process": True}, "Extra inputs"),
    ({"id": "a", "match": {"name": "x"}, "active_when": {"gpu_active": True}, "cap_fleet": {"gpu_jobs": 0}}, "GpuActive"),
    ({"id": "a", "match": {"name": "x"}, "active_when": {"gpu_active": {"min_busy": 0}}, "cap_fleet": {"gpu_jobs": 0}},
     "greater than 0"),
    ({"id": "a", "match": {"name": "x"}, "active_when": {"gpu_active": {"min_busy": 1.5}}, "cap_fleet": {"gpu_jobs": 0}},
     "less than or equal to 1"),
])
def test_protection_rule_validation(rule, match):
    with pytest.raises(ValidationError, match=match):
        prot.ProtectionConfig.model_validate({"rule": [rule]})


def test_no_action_can_target_a_protected_process():
    """S16 structurally: every action field is a fleet-side verb."""
    assert set(prot.ACTION_KEYS) == {"reserve", "cap_fleet", "lower_fleet", "pause_fleet", "protect", "evict"}
    for k in prot.ACTION_KEYS:
        model = prot.Actions.model_fields[k].annotation.__args__[0]
        assert not any("pid" in f or "target" in f or "signal" in f for f in model.model_fields), k


# ------------------------------------------------------------------ schemas

def test_contract_schemas_are_fresh():
    rendered = schemas.render_all()
    on_disk = {p.name: p.read_text(encoding="utf-8") for p in schemas.ROOT.glob("*.schema.json")}
    assert on_disk == rendered, "run `python -m oarbank.contracts.schemas`"


def test_generated_registry_docs_are_fresh():
    from oarbank.contracts import docs
    for name, fn in docs.RENDERED.items():
        assert (docs.DOCS / name).read_text(encoding="utf-8") == fn(), "run `python -m oarbank.contracts.docs`"


def test_every_operation_has_a_handler_and_a_console_form():
    from oarbank.coordinator import ops as runtime
    assert set(runtime.HANDLERS) == set(ops.REGISTRY), "the registry and the handlers behind /api/v1/ops differ"
    assert not [o.id for o in ops.OPS if not o.gui]


def test_parity_audit_has_zero_gaps():
    """Every operation on the API, the CLI and the console; every explain kind on all three; every reason code's
    remedies are operations (docs/design/parity.md is the generated report)."""
    from oarbank.contracts import parity
    assert parity.gaps() == []
