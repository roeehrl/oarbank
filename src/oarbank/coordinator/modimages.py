"""Container images on the coordinator side (oarbank-sdk spec/sandbox.md, "Image sets").

A module's jobs run digest-pinned images through the agent's broker: the static `[sandbox].containers` entries, or
images of its `[[sandbox.container_sets]]` (a registry and repository prefix with a pinned cosign key). The coordinator
checks what it can without a registry: every image a job lists (jobs.enqueue `images`) is digest-pinned and is a static
entry or under a set's prefix, and the job's stage reserves the `containers` pool. The agent verifies the signatures
before it pulls, and reports each set image an attempt ran; the first run of each digest per module is recorded and
audited here.
"""
import time

from oarbank_sdk import images as I

from .db import DB

MAX_IMAGES_PER_JOB = 16


class ImageRefused(ValueError):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.status, self.code, self.detail = status, code, detail


def check_job_images(man, stage: str | None, images) -> list[str]:
    """The job's images, as given, once each is approved: digest-pinned, a static entry or inside a set, for a stage
    that reserves the containers pool. Raises ImageRefused (422 bad_images or image_not_approved)."""
    if images in (None, []):
        return []
    if not isinstance(images, list) or not all(isinstance(i, str) for i in images) or len(images) > MAX_IMAGES_PER_JOB:
        raise ImageRefused(422, "bad_images", f"images is a list of at most {MAX_IMAGES_PER_JOB} digest-pinned references")
    st = man.stage(stage or man.default_stage() or "")
    if st is None or "containers" not in st.requires.pools:
        raise ImageRefused(422, "bad_images", f"stage {stage or man.default_stage()!r} reserves no containers pool, so its "
                           "jobs have no container broker")
    static = set()
    for c in man.sandbox.containers:
        repo, _, digest = I.normalize(c.image)
        static.add((repo, digest))
    for ref in images:
        try:
            repo, _, digest = I.normalize(ref)
        except I.ImageError as e:
            raise ImageRefused(422, "image_not_approved", str(e))
        if not digest:
            raise ImageRefused(422, "image_not_approved", f"{ref} is not pinned by digest")
        if (repo, digest) not in static and not any(cs.covers(repo) for cs in man.sandbox.container_sets):
            raise ImageRefused(422, "image_not_approved", f"{ref} is neither an approved image of the module nor inside one "
                               "of its container sets")
    return list(dict.fromkeys(images))


def set_requests(man, bundle) -> list[dict]:
    """The sets as approval shows and digests them: prefix, platform, the key's SHA-256 (never a list of digests)."""
    out = []
    for cs in man.sandbox.container_sets:
        out.append({"name": cs.name, "registry": cs.registry, "repository": cs.repository, "platform": cs.platform,
                    "key_sha256": I.key_sha256(I.load_key(bundle, cs)), "index": cs.index})
    return sorted(out, key=lambda c: c["name"])


def release_sets(man, bundle) -> list[dict]:
    """The sets as a release carries them to agents: the key itself (PEM), which the agent verifies with."""
    return [{"name": cs.name, "registry": cs.registry, "repository": cs.repository, "platform": cs.platform,
             "key": I.load_key(bundle, cs), **({"index": cs.index} if cs.index else {})} for cs in man.sandbox.container_sets]


def record_runs(db: DB, module: str, node_id: str, attempt_id: int, ran: list) -> list[str]:
    """Record the set images an attempt ran (the agent's report: [{set, image}]). The first run of each digest per module
    is a row in module_images, the event container_image_first_run and an audit row. Returns the new digests."""
    from . import audit, modcalls
    try:
        mi = modcalls.info(module)
    except KeyError:
        return []
    keys = {}
    new = []
    for r in ran or []:
        image, set_name = str(r.get("image") or ""), str(r.get("set") or "")
        try:
            repo, _, digest = I.normalize(image)
        except I.ImageError:
            continue
        cs = next((c for c in mi.manifest.sandbox.container_sets if c.name == set_name and c.covers(repo)), None)
        if not digest or cs is None:
            continue
        if db.one("SELECT 1 FROM module_images WHERE module=? AND digest=?", (module, digest)):
            continue
        if set_name not in keys:
            keys[set_name] = I.key_sha256(I.load_key(mi.path, cs))
        db.x("INSERT INTO module_images(module,digest,image,set_name,key_sha256,first_run_at,node_id,attempt_id) "
             "VALUES(?,?,?,?,?,?,?,?)", (module, digest, image, set_name, keys[set_name], time.time(), node_id, attempt_id))
        db.event("container_image_first_run", node_id=node_id, attempt_id=attempt_id,
                 reason=f"{module} {image} (set {set_name}, key {keys[set_name][:16]})"[:300])
        audit.append(db, actor=f"node:{node_id}", source="system", operation="containers.first_run", category="create",
                     target_type="module", target_id=module, outcome="ok", request_id=audit.request_id(),
                     after={"image": image, "digest": digest, "set": set_name, "key_sha256": keys[set_name],
                            "attempt_id": attempt_id})
        new.append(digest)
    return new


def first_runs(db: DB, module: str, limit: int = 200) -> list[dict]:
    return db.q("SELECT * FROM module_images WHERE module=? ORDER BY first_run_at DESC LIMIT ?", (module, limit))
