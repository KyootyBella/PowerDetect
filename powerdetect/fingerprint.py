"""Deterministic fingerprints of deobfuscated PowerShell.

  structural - hash of the normalized "skeleton" of all layers. Volatile parts
               (URLs, IPs, numbers, base64, paths, variable names, aliases,
               quoting, whitespace, case) are abstracted away, so the same
               tool/technique with different C2 or different obfuscation
               collapses to the same fingerprint.
  payload    - same, but only for the innermost decoded layer (clusters the
               same payload delivered through different loaders).
  behavior   - hash of the sorted rule IDs + obfuscation techniques that fired.
  exact      - hash of the full deobfuscated text (no abstraction).
"""
from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

FP_LEN = 16
_RANK = {"LOW": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}

_ALIASES = {
    "iex": "invoke-expression", "iwr": "invoke-webrequest", "wget": "invoke-webrequest",
    "curl": "invoke-webrequest", "irm": "invoke-restmethod", "icm": "invoke-command",
    "saps": "start-process", "start": "start-process", "sal": "set-alias",
    "gci": "get-childitem", "ls": "get-childitem", "dir": "get-childitem",
    "gc": "get-content", "cat": "get-content", "type": "get-content",
    "sc": "set-content", "ac": "add-content", "gwmi": "get-wmiobject",
    "iwmi": "invoke-wmimethod", "gcim": "get-ciminstance", "ni": "new-item",
    "rm": "remove-item", "del": "remove-item", "ri": "remove-item",
    "sv": "set-variable", "gv": "get-variable", "set": "set-variable",
    "%": "foreach-object", "foreach": "foreach-object", "?": "where-object",
    "where": "where-object", "echo": "write-output", "write": "write-output",
    "spps": "stop-process", "kill": "stop-process", "gp": "get-itemproperty",
    "sp": "set-itemproperty", "ipmo": "import-module",
}
_AUTOMATIC = {"null", "true", "false", "_", "args", "input", "this", "psitem", "home",
              "pshome", "shellid", "psscriptroot", "pscommandpath", "myinvocation",
              "host", "error", "executioncontext", "profile", "pid", "pwd"}

_URL = re.compile(r"(?:https?|ftp)://[^\s'\"`)<>;|]+")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
_B64 = re.compile(r"[a-z0-9+/]{40,}={0,2}")
_BYTES = re.compile(r"(?:0x[0-9a-f]{1,2}\s*,\s*){8,}0x[0-9a-f]{1,2}")
_PATH = re.compile(r"(?:[a-z]:|\\\\[\w.$-]+|%\w+%|\$env:\w+)(?:\\[^\\\s'\";|,)]*)+")
_NUM = re.compile(r"(?<![\w$<])(?:0x[0-9a-f]+|\d+)\b")
_DQ_PLAIN = re.compile(r'"([^"$`]*)"')
_CALLOP = re.compile(r"(?<![\w)\]])([&.])\s*'([\w.-]+)'")
_BARE_STR = re.compile(r"'([\w.-]+)'")
_VAR = re.compile(r"\$(\{[^}]+\}|(?:env|global|script|local|private|using):\w+|\w+)")
_ALIAS_RE = re.compile(r"(?<![\w.$:\\/-])(" + "|".join(
    re.escape(a) for a in sorted(_ALIASES, key=len, reverse=True)) + r")(?![\w-])")
_WS = re.compile(r"\s+")
_OPS = re.compile(r"\s*([();,=|{}\[\]+])\s*")


def skeleton(text: str) -> str:
    t = text.lower()
    t = _URL.sub("<url>", t)
    t = _IP.sub("<ip>", t)
    t = _BYTES.sub("<bytes>", t)
    t = _B64.sub("<b64>", t)
    t = _PATH.sub("<path>", t)
    t = _NUM.sub("<n>", t)
    t = _DQ_PLAIN.sub(lambda m: "'" + m.group(1).replace("'", "''") + "'", t)
    t = _CALLOP.sub(lambda m: m.group(2), t)        # &'iex' -> iex
    t = _BARE_STR.sub(lambda m: m.group(1), t)       # 'net.webclient' -> net.webclient

    names: dict[str, str] = {}

    def var(m: re.Match) -> str:
        name = m.group(1)
        if name in _AUTOMATIC or ":" in name and name.startswith("env:"):
            return "$" + name
        if name not in names:
            names[name] = f"v{len(names) + 1}"
        return "$" + names[name]

    t = _VAR.sub(var, t)
    t = _ALIAS_RE.sub(lambda m: _ALIASES[m.group(1)], t)
    t = _WS.sub(" ", t)
    t = _OPS.sub(r"\1", t)
    return t.strip()


def _h(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:FP_LEN]


def compute(layer_texts: list[str], rule_ids: list[str], techniques: list[str]) -> tuple[dict, str]:
    skels = [skeleton(t) for t in layer_texts]
    full = "\n".join(skels)
    fps = {
        "structural": _h(full),
        "payload": _h(skels[-1] if skels else ""),
        "behavior": _h("|".join(sorted(rule_ids)) + "#" + ",".join(sorted(techniques))),
        "exact": _h("\n".join(layer_texts)),
    }
    return fps, full


# ---------------------------------------------------------------- known fingerprints
@dataclass
class KnownEntry:
    type: str          # structural | payload | behavior | exact
    value: str
    label: str
    verdict: str | None = None


FP_TYPES = ("structural", "payload", "behavior", "exact")


def toml_files(path: Path | str) -> list[Path]:
    """A .toml file, or every .toml file in a folder (sorted; names starting with '_' skipped)."""
    p = Path(path)
    if p.is_dir():
        return sorted(f for f in p.glob("*.toml") if not f.name.startswith("_"))
    return [p]


class FingerprintDB:
    """One or more TOML files (or folders of them) of analyst-labelled fingerprints:

        [[fingerprint]]
        type = "structural"
        value = "1a2b3c4d5e6f7a8b"
        label = "WebClient download cradle"
        verdict = "MALICIOUS"   # optional; "LOW" allow-lists a known-good script

    Extra keys (sample, mitre, reference, author ...) are allowed and ignored here.
    """

    def __init__(self, *paths: Path | str):
        self.entries: list[KnownEntry] = []
        for path in paths:
            for f in toml_files(path):
                self._load(f)

    def _load(self, path: Path) -> None:
        with open(path, "rb") as f:
            cfg = tomllib.load(f)
        for e in cfg.get("fingerprint", []):
            v = e.get("verdict")
            if v is not None and v not in _RANK:
                raise ValueError(f"{path.name}: bad verdict {v!r} for fingerprint {e.get('value')}")
            if e.get("type", "structural") not in FP_TYPES:
                raise ValueError(f"{path.name}: bad fingerprint type {e.get('type')!r}")
            self.entries.append(KnownEntry(e.get("type", "structural"), e["value"].lower(),
                                           e.get("label", ""), v))

    def match(self, fps: dict) -> list[KnownEntry]:
        return [e for e in self.entries if fps.get(e.type) == e.value]


def toml_str(s: str) -> str:
    """A TOML basic string (JSON string escaping is valid TOML)."""
    import json
    return json.dumps(s, ensure_ascii=False)


EXPORT_HEADER = """\
# PowerDetect fingerprint export.
# Fill in each label, then use the file with --known, or contribute it
# (see CONTRIBUTING.md). Before sharing: replace anything from your own
# environment in `sample` (host names, user names, internal domains) and
# check the fingerprint still matches with tools/check_fingerprints.py.
"""


def export_toml(reports, path: Path | str) -> int:
    """Write a labelling template for every non-LOW command (deduped by structural fp)."""
    seen, out = set(), [EXPORT_HEADER]
    for r in reports:
        fp = r.fingerprints["structural"]
        if r.verdict == "LOW" or fp in seen:
            continue
        seen.add(fp)
        mitre = sorted({t.strip() for h in r.hits for t in (h.mitre or "").split(",") if t.strip()})
        out.append(f"# rules: {', '.join(h.id for h in r.hits[:6])}\n"
                   f"[[fingerprint]]\ntype = \"structural\"\nvalue = \"{fp}\"\n"
                   f"label = \"TODO\"\nverdict = \"{r.verdict}\"\n"
                   f"mitre = {toml_str(', '.join(mitre))}\n"
                   f"sample = {toml_str(r.raw)}\n")
    Path(path).write_text("\n".join(out), encoding="utf-8")
    return len(seen)
