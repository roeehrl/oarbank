"""The YAML that settings export writes and import reads (docs/design/settings.md, "Settings as code"): a small,
strict subset of YAML 1.2, so the coordinator needs no YAML library and every file it writes reads back the same.

- Block mappings (`key: value`, nested by indentation) and block sequences (`- value`); a key is a plain word
  (letters, digits and `_ . / @ -`, not starting with `-`) or a JSON string.
- Values: `null` (`~`), `true` / `false`, numbers, plain words, JSON strings (`"..."`), single-quoted strings, and
  flow collections written as JSON (`[1, "a"]`, `{"start": "22:00"}`; a flow list of plain words also reads).
- Two tags: `!reset` (delete this value: import only) and `!locked <value>` (the value, locked at its scope).
- `#` starts a comment at the start of a line or after a space, outside quotes.

Anything else is refused with its line number (YamlError), never guessed."""
import json
import re

PLAIN_KEY = re.compile(r"^[A-Za-z0-9_./@][A-Za-z0-9_./@-]*$")
PLAIN_WORD = re.compile(r"^[A-Za-z_./@][A-Za-z0-9_./@+:-]*$")
NUMBER = re.compile(r"^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?$")
RESERVED = {"null", "true", "false", "yes", "no", "on", "off", "~", "y", "n"}


class YamlError(ValueError):
    def __init__(self, line: int, msg: str):
        super().__init__(f"line {line}: {msg}")
        self.line, self.msg = line, msg


class Reset:
    """`!reset`: the value is deleted at this scope."""

    def __repr__(self):
        return "!reset"

    def __eq__(self, other):
        return isinstance(other, Reset)

    def __hash__(self):
        return 0


RESET = Reset()


class Locked:
    """`!locked <value>`: the value, locked at its scope."""

    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"!locked {self.value!r}"

    def __eq__(self, other):
        return isinstance(other, Locked) and other.value == self.value


# ------------------------------------------------------------------ writing

def _scalar(v) -> str:
    if isinstance(v, Locked):
        return "!locked " + _scalar(v.value)
    if isinstance(v, Reset):
        return "!reset"
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return json.dumps(v)
    if isinstance(v, str):
        if PLAIN_WORD.fullmatch(v) and v.lower() not in RESERVED and len(v) <= 200:
            return v
        return json.dumps(v, ensure_ascii=False)
    return json.dumps(v, sort_keys=True, ensure_ascii=False)


def _key(k) -> str:
    k = str(k)
    return k if PLAIN_KEY.fullmatch(k) and k.lower() not in RESERVED else json.dumps(k, ensure_ascii=False)


def _block(v) -> bool:
    """Whether a value is written as a nested block (a non-empty mapping of the document's structure)."""
    return isinstance(v, dict) and bool(v)


def dump(doc: dict, header: str = "") -> str:
    """The document as YAML. Mappings nest as blocks; every list, and a mapping given as Flow(...), is one JSON line."""
    lines = [f"# {x}" if x else "#" for x in header.splitlines()] if header else []

    def walk(d: dict, ind: int):
        for k, v in d.items():
            pad = " " * ind
            if isinstance(v, Flow):
                lines.append(f"{pad}{_key(k)}: {_scalar(v.value)}")
            elif _block(v):
                lines.append(f"{pad}{_key(k)}:")
                walk(v, ind + 2)
            else:
                lines.append(f"{pad}{_key(k)}: {_scalar(v)}")
    walk(doc, 0)
    return "\n".join(lines) + "\n"


class Flow:
    """A mapping written on one line as JSON (a setting's object value: a schedule, a protection section)."""

    def __init__(self, value):
        self.value = value


# ------------------------------------------------------------------ reading

def _strip_comment(s: str) -> str:
    out, q = [], None
    for i, ch in enumerate(s):
        if q:
            out.append(ch)
            if ch == "\\" and q == '"':
                continue
            if ch == q and not (q == '"' and i and s[i - 1] == "\\"):
                q = None
            continue
        if ch in "\"'":
            q = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _value(text: str, line: int):
    t = text.strip()
    if t.startswith("!reset"):
        if t != "!reset":
            raise YamlError(line, "!reset takes no value")
        return RESET
    if t.startswith("!locked"):
        rest = t[len("!locked"):].strip()
        if not rest:
            raise YamlError(line, "!locked needs a value on the same line")
        return Locked(_value(rest, line))
    if t.startswith("!"):
        raise YamlError(line, f"unknown tag {t.split()[0]} (only !reset and !locked)")
    if t in ("null", "~", ""):
        return None
    if t == "true":
        return True
    if t == "false":
        return False
    if NUMBER.fullmatch(t):
        return json.loads(t)
    if t.startswith('"'):
        try:
            return json.loads(t)
        except ValueError:
            raise YamlError(line, f"not a valid double-quoted string: {t[:60]}")
    if t.startswith("'"):
        if len(t) < 2 or not t.endswith("'"):
            raise YamlError(line, f"not a valid single-quoted string: {t[:60]}")
        return t[1:-1].replace("''", "'")
    if t[0] in "[{":
        try:
            return json.loads(t)
        except ValueError:
            pass
        if t.startswith("[") and t.endswith("]") and not any(c in t[1:-1] for c in "[]{}\"'"):
            inner = t[1:-1].strip()
            return [_value(x, line) for x in inner.split(",")] if inner else []
        raise YamlError(line, f"a flow collection is written as JSON: {t[:60]}")
    if t.lower() in ("yes", "no", "on", "off"):
        raise YamlError(line, f"{t!r} is ambiguous: write true or false (or quote it)")
    if t[0] in "&*|>%@`":
        raise YamlError(line, f"this file's YAML has no anchors, aliases or block scalars: {t[:60]}")
    return t


def _split_key(body: str, line: int) -> tuple[str, str]:
    """`key: rest` (the key plain or a JSON string)."""
    if body.startswith('"'):
        dec = json.JSONDecoder()
        try:
            k, end = dec.raw_decode(body)
        except ValueError:
            raise YamlError(line, "a quoted key is a JSON string")
        rest = body[end:]
        if not rest.startswith(":"):
            raise YamlError(line, "expected ':' after the key")
        return k, rest[1:]
    m = re.match(r"^([^:\s][^:]*?):(\s|$)", body)
    if not m:
        raise YamlError(line, f"expected 'key: value', got {body[:60]!r}")
    k = m.group(1)
    if not PLAIN_KEY.fullmatch(k):
        raise YamlError(line, f"a key is a plain word or a JSON string, got {k!r}")
    return k, body[m.end(1) + 1:]


def load(text: str):
    """The document a YAML text holds (YamlError with the line otherwise)."""
    rows = []
    for no, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[:len(raw) - len(raw.lstrip())]:
            raise YamlError(no, "indent with spaces, not tabs")
        s = _strip_comment(raw)
        if s.strip() in ("", "---", "..."):
            continue
        rows.append((no, len(s) - len(s.lstrip(" ")), s.strip()))
    if not rows:
        return {}
    pos = [0]

    def parse(ind: int):
        no, i, body = rows[pos[0]]
        if body.startswith("- ") or body == "-":
            out = []
            while pos[0] < len(rows):
                no, i, body = rows[pos[0]]
                if i < ind:
                    break
                if i > ind:
                    raise YamlError(no, "unexpected indentation")
                if not (body.startswith("- ") or body == "-"):
                    raise YamlError(no, "a list item starts with '- '")
                pos[0] += 1
                item = body[1:].strip()
                if not item:
                    if pos[0] >= len(rows) or rows[pos[0]][1] <= ind:
                        out.append(None)
                    else:
                        out.append(parse(rows[pos[0]][1]))
                elif re.match(r'^("[^"]*"|[^:\s\[{"\'][^:]*?):(\s|$)', item) and not item.startswith(("[", "{")):
                    # `- key: value` starts a mapping item; its other keys sit under it, two spaces in
                    rows.insert(pos[0], (no, ind + 2, item))
                    out.append(parse(ind + 2))
                else:
                    out.append(_value(item, no))
            return out
        out = {}
        while pos[0] < len(rows):
            no, i, body = rows[pos[0]]
            if i < ind:
                break
            if i > ind:
                raise YamlError(no, "unexpected indentation")
            if body.startswith("- "):
                raise YamlError(no, "a list item where a key was expected")
            k, rest = _split_key(body, no)
            if k in out:
                raise YamlError(no, f"the key {k!r} appears twice")
            pos[0] += 1
            if rest.strip():
                out[k] = _value(rest, no)
            elif pos[0] < len(rows) and rows[pos[0]][1] > ind:
                out[k] = parse(rows[pos[0]][1])
            elif pos[0] < len(rows) and rows[pos[0]][1] == ind and rows[pos[0]][2].startswith("- "):
                out[k] = parse(ind)                   # a list at the key's own indentation (common YAML style)
            else:
                out[k] = None
        return out

    first_ind = rows[0][1]
    doc = parse(first_ind)
    if pos[0] < len(rows):
        raise YamlError(rows[pos[0]][0], "unexpected indentation")
    return doc


def plain(v):
    """A loaded value with its tags dropped (Locked -> its value; Reset stays): for comparing."""
    if isinstance(v, Locked):
        return plain(v.value)
    if isinstance(v, dict):
        return {k: plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [plain(x) for x in v]
    return v
