"""Generate match-vectors.json: the console's preview matcher (oarbank.contracts.protection_match) run over
every match key, tree scope and edge case; the Rust matcher must give the same answers (D20).

    (from the repository root) uv run --extra dev python rust/crates/oarbank-protection/vectors/gen.py
"""
import json
from pathlib import Path

from oarbank.contracts.protection_match import group

OUT = Path(__file__).parent / "match-vectors.json"
XCODE_REQ = 'anchor apple and identifier "com.apple.dt.Xcode"'
CHROME_REQ = 'anchor apple generic and certificate leaf[subject.OU] = "EQHXZ8M8AV"'

PROCESSES = [
    # a protected app's tree; pid 13 claims pid 10 as parent but started earlier (a reused ppid)
    {"pid": 10, "ppid": 1, "start_us": 1000, "path": "/Applications/GPU App.app/Contents/Engine/bin/1/engine",
     "argv": ["engine"]},
    {"pid": 11, "ppid": 10, "start_us": 1100, "path": "/usr/bin/python3", "argv": ["python3", "train.py"]},
    {"pid": 12, "ppid": 11, "start_us": 1200, "path": "/bin/sh", "argv": ["sh", "-c", "x"]},
    {"pid": 13, "ppid": 10, "start_us": 500, "path": "/bin/zsh", "argv": ["zsh"]},
    {"pid": 14, "ppid": 12, "start_us": 1200, "path": "/usr/bin/tee", "argv": ["tee"]},  # same start as parent
    # a signed browser and its helpers (same team, different identifiers)
    {"pid": 20, "ppid": 1, "start_us": 2000, "path": "/Applications/Web Browser.app/Contents/MacOS/Web Browser",
     "team_id": "EQHXZ8M8AV", "signing_id": "com.example.browser", "bundle_id": "com.example.browser",
     "requirements_met": [CHROME_REQ], "argv": ["Web Browser"]},
    {"pid": 21, "ppid": 20, "start_us": 2100, "path": "/Applications/Web Browser.app/Contents/Frameworks/Helper",
     "team_id": "EQHXZ8M8AV", "signing_id": "com.example.browser.helper", "bundle_id": "com.example.browser.helper",
     "comm": "Web Browser Help", "argv": ["Helper", "--type=renderer"]},
    {"pid": 22, "ppid": 1, "start_us": 2200, "path": "/Applications/Other.app/Contents/MacOS/Other",
     "team_id": "OTHERTEAM1", "signing_id": "com.example.other", "bundle_id": "com.example.other",
     "argv": ["Other"]},
    # python processes told apart by argv
    {"pid": 30, "ppid": 1, "start_us": 3000, "path": "/Users/o/venvs/mlx/bin/python",
     "argv": ["python", "train.py", "--lr", "1e-4"]},
    {"pid": 31, "ppid": 1, "start_us": 3100, "path": "/Users/o/venvs/mlx/bin/python", "argv": ["python", "eval.py"]},
    {"pid": 32, "ppid": 1, "start_us": 3200, "path": "/Users/o/venvs/mlx/bin/python"},  # argv unreadable
    {"pid": 33, "ppid": 1, "start_us": 3300, "path": "/Users/o/venvs/mlx/bin/python", "argv": []},
    {"pid": 34, "ppid": 1, "start_us": 3400, "path": "/Users/o/bin/run", "argv": ["run", "--Mode=TRAIN", "épreuve"]},
    # code-signing requirement
    {"pid": 40, "ppid": 1, "start_us": 4000, "path": "/Applications/Xcode.app/Contents/MacOS/Xcode",
     "requirements_met": [XCODE_REQ], "argv": ["Xcode"]},
    {"pid": 41, "ppid": 40, "start_us": 4100, "path": "/usr/bin/clang", "argv": ["clang"]},
    {"pid": 42, "ppid": 41, "start_us": 4200, "path": "/usr/bin/ld", "argv": ["ld", "-o", "a.out"]},
    {"pid": 50, "ppid": 1, "start_us": 5000, "path": "/Applications/zoom.us.app/Contents/MacOS/zoom.us",
     "bundle_id": "us.zoom.xos", "argv": ["zoom.us"]},
    # odd identities: empty team and bundle strings, a self-parented process, a path ending in a slash
    {"pid": 60, "ppid": 1, "start_us": 6000, "path": "/opt/tools/a", "team_id": "", "bundle_id": "", "argv": ["a"]},
    {"pid": 61, "ppid": 60, "start_us": 6100, "path": "/opt/tools/b", "team_id": "", "argv": ["b"]},
    {"pid": 70, "ppid": 70, "start_us": 7000, "path": "/opt/loop/self", "argv": ["self"]},
    {"pid": 71, "ppid": 70, "start_us": 7100, "path": "/opt/loop/child", "argv": ["child"]},
    {"pid": 80, "ppid": 1, "start_us": 8000, "path": "/opt/dir/", "argv": ["dir"]},
    {"pid": 81, "ppid": 1, "start_us": 8100, "path": "relative-tool", "comm": "rt", "argv": ["rt"]},
    # Linux and Windows processes: comm is the kernel's short name (15 characters on Linux), the image file name on
    # Windows; Windows paths keep their backslashes
    {"pid": 90, "ppid": 1, "start_us": 9000, "path": "/usr/lib/firefox/firefox", "comm": "firefox",
     "argv": ["/usr/lib/firefox/firefox", "-contentproc"]},
    {"pid": 91, "ppid": 1, "start_us": 9100, "path": r"C:\Program Files\Blender Foundation\Blender 4.2\blender.exe",
     "comm": "blender.exe", "argv": [r"C:\Program Files\Blender Foundation\Blender 4.2\blender.exe", "--background",
                                     "scene.blend"]},
    # another account's processes the agent may not inspect: an unreadable path (Linux), unreadable arguments
    # (Windows); an unreadable fact counts as satisfying its key, a readable one still decides
    {"pid": 100, "ppid": 1, "start_us": 10000, "comm": "python3", "argv": ["python3", "train.py"]},
    {"pid": 101, "ppid": 1, "start_us": 10100, "path": r"C:\Users\b\venv\Scripts\python.exe", "comm": "python.exe"},
]


def case(name, match, tree="self"):
    return {"name": name, "match": match, "tree": tree, "expected": sorted(p["pid"] for p in group(PROCESSES, match, tree))}


CASES = [
    # every key on its own
    case("requirement", {"requirement": XCODE_REQ}),
    case("requirement + descendants", {"requirement": XCODE_REQ}, "descendants"),
    case("requirement not met", {"requirement": "anchor apple"}),
    case("team_id", {"team_id": "EQHXZ8M8AV"}),
    case("identifier", {"identifier": "com.example.browser.helper"}),
    case("bundle_id string", {"bundle_id": "us.zoom.xos"}),
    case("bundle_id list", {"bundle_id": ["us.zoom.xos", "com.apple.FaceTime"]}),
    case("path_prefix", {"path_prefix": "/Users/o/venvs/mlx/bin/"}),
    case("path_contains in the path", {"path_contains": "Engine/bin"}),
    case("path_contains in an argument", {"path_contains": "eval.py"}),
    case("path_contains across path and argument", {"path_contains": "python train.py"}),
    case("path_contains never sees argv[0]", {"path_contains": "engine"}),
    case("name is p_comm", {"name": "Web Browser Help"}),
    case("name falls back to the path's last component", {"name": "clang"}),
    case("name does not see the full basename when p_comm is set", {"name": "Helper"}),
    case("name of a relative path with p_comm", {"name": "rt"}),
    case("a path ending in a slash has an empty last component", {"name": "dir"}),
    case("argv_regex", {"argv_regex": r"train\.py"}),
    case("argv_regex anchored on the joined argv", {"argv_regex": r"^python eval\.py$"}),
    case("argv_regex empty argv matches ^$, unreadable argv always", {"argv_regex": "^$"}),
    case("argv_regex case-insensitive flag", {"argv_regex": "(?i)mode=train"}),
    case("argv_regex lookahead", {"argv_regex": r"python (?=train)"}),
    case("argv_regex negative lookahead", {"argv_regex": r"^python (?!train)"}),
    case("argv_regex backreference", {"argv_regex": r"(-)\1?lr"}),
    case("argv_regex unicode word", {"argv_regex": r"\bépreuve\b"}),
    case("argv_regex alternation and classes", {"argv_regex": r"^(ld|clang)( -o [a-z.]+)?$"}),
    # Linux and Windows identities
    case("a Windows path prefix", {"path_prefix": "C:\\Program Files\\Blender Foundation\\"}),
    case("a Windows image name", {"name": "blender.exe"}),
    case("a Linux comm", {"name": "firefox"}),
    # unreadable facts
    case("an unreadable path satisfies path_prefix", {"path_prefix": "/opt/trainer/"}),
    case("an unreadable path with a readable comm that differs", {"path_prefix": "/opt/trainer/", "name": "trainer"}),
    case("unreadable arguments satisfy argv_regex", {"argv_regex": r"train\.py"}),
    case("path_contains held by a readable path, arguments unreadable", {"path_contains": r"venv\Scripts"}),
    case("path_contains with a readable path that lacks it and unreadable arguments", {"path_contains": "--lr"}),
    case("a readable argv decides argv_regex, an unreadable path does not", {"argv_regex": "^python3 eval"}),
    # several keys: all must hold
    case("path prefix + argv regex", {"path_prefix": "/Users/o/venvs/mlx/bin/python", "argv_regex": r"train\.py"},
         "descendants"),
    case("team + bundle", {"team_id": "EQHXZ8M8AV", "bundle_id": ["com.example.browser"]}),
    case("team + identifier mismatch", {"team_id": "OTHERTEAM1", "identifier": "com.example.browser"}),
    case("every key at once", {"requirement": CHROME_REQ, "team_id": "EQHXZ8M8AV", "identifier": "com.example.browser",
                               "bundle_id": ["com.example.browser"], "path_prefix": "/Applications/Web Browser.app/",
                               "path_contains": "MacOS/Web", "name": "Web Browser"}),
    # empty keys are no keys
    case("empty name is no key", {"name": "", "path_prefix": "/opt/"}),
    case("empty bundle string is no key", {"bundle_id": "", "path_prefix": "/opt/tools/"}),
    case("empty bundle list is no key", {"bundle_id": [], "path_prefix": "/opt/tools/"}),
    case("a list holding the empty bundle matches an empty bundle id", {"bundle_id": [""]}),
    case("empty team is no key", {"team_id": "", "path_prefix": "/opt/tools/a"}),
    case("only empty keys match everything", {"requirement": "", "identifier": "", "path_contains": "",
                                              "argv_regex": ""}),
    # trees
    case("path_contains + descendants skips a reused ppid", {"path_contains": "Engine/bin"}, "descendants"),
    case("path_contains self", {"path_contains": "Engine/bin"}, "self"),
    case("descendants of a mid-tree process", {"path_prefix": "/usr/bin/python3"}, "descendants"),
    case("descendants include a child started with its parent", {"path_prefix": "/bin/sh"}, "descendants"),
    case("descendants of a self-parented process", {"path_prefix": "/opt/loop/self"}, "descendants"),
    case("team + bundle, same_team pulls helpers", {"team_id": "EQHXZ8M8AV", "bundle_id": ["com.example.browser"]},
         "same_team"),
    case("requirement, same_team pulls helpers", {"requirement": CHROME_REQ}, "same_team"),
    case("same_team without a team keeps the direct matches", {"bundle_id": "us.zoom.xos"}, "same_team"),
    case("same_team ignores empty team ids", {"path_prefix": "/opt/tools/a"}, "same_team"),
    case("self with several direct matches", {"path_prefix": "/Users/o/"}, "self"),
    case("no match", {"bundle_id": ["com.nobody"]}, "descendants"),
    case("no match same_team", {"team_id": "NOBODY0000"}, "same_team"),
]

OUT.write_text(json.dumps({
    "comment": "Generated by gen.py from oarbank.contracts.protection_match (the console's preview matcher). "
               "expected: the sorted pids of the rule's group. Do not edit by hand; regenerate.",
    "processes": PROCESSES, "cases": CASES}, indent=1, ensure_ascii=False) + "\n")
print(f"{len(CASES)} cases over {len(PROCESSES)} processes -> {OUT}")
