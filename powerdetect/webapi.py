"""JSON-in / JSON-out API used by the browser version (Pyodide) and other embedders.

Everything here is a thin wrapper around engine.analyze, so the website gives
exactly the same verdicts as the CLI.
"""
from __future__ import annotations

import csv
import io
import json
import tempfile
from collections import defaultdict
from pathlib import Path

from .engine import RANK, Rules, analyze
from .fingerprint import FingerprintDB, export_toml

CMD_COLUMNS = ("ProcessCommandLine", "InitiatingProcessCommandLine", "CommandLine",
               "processCommandLine", "commandLine", "ScriptContent")
MAX_COMMANDS = 20000

_state: dict = {"rules": None, "db": None, "reports": []}


def init(db_path: str | None = None) -> str:
    rules = Rules()
    db = FingerprintDB(db_path) if db_path and Path(db_path).exists() else None
    _state.update(rules=rules, db=db, reports=[])
    return json.dumps({"rules": len(rules.rules), "combos": len(rules.combos),
                       "db": len(db.entries) if db else 0, "tactics": rules.tactics})


def _walk_json(obj, out: list[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in CMD_COLUMNS and isinstance(v, str) and v.strip():
                out.append(v)
            else:
                _walk_json(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _walk_json(v, out)


def collect(text: str, kind: str) -> list[str]:
    """kind: lines | whole | csv | json"""
    text = text.lstrip("﻿")
    cmds: list[str] = []
    if kind == "csv":
        for row in csv.DictReader(io.StringIO(text)):
            for col in CMD_COLUMNS:
                if (row.get(col) or "").strip():
                    cmds.append(row[col])
                    break
    elif kind == "json":
        _walk_json(json.loads(text), cmds)
    elif kind == "whole":
        if text.strip():
            cmds.append(text)
    else:
        cmds = [l for l in text.splitlines() if l.strip()]
    return list(dict.fromkeys(cmds))


def _clusters(reports) -> list[dict]:
    groups: dict[str, list[int]] = defaultdict(list)
    for i, r in enumerate(reports):
        groups[r.fingerprints["structural"]].append(i)
    out = []
    for fp, idx in groups.items():
        members = [reports[i] for i in idx]
        worst = max((r.verdict for r in members), key=RANK.__getitem__)
        if len(idx) < 2 and worst == "LOW":
            continue
        label = next((r.known[0]["label"] for r in members if r.known), "")
        out.append({"fingerprint": fp, "count": len(idx), "verdict": worst, "label": label,
                    "members": [i + 1 for i in idx], "skeleton": members[0].skeleton})
    out.sort(key=lambda c: (-RANK[c["verdict"]], -c["count"], c["fingerprint"]))
    return out


def run(text: str, kind: str = "lines", use_db: bool = True) -> str:
    rules: Rules = _state["rules"] or Rules()
    db = _state["db"] if use_db else None
    cmds = collect(text, kind)
    truncated = max(0, len(cmds) - MAX_COMMANDS)
    cmds = cmds[:MAX_COMMANDS]
    reports = [analyze(c, rules, db) for c in cmds]
    _state["reports"] = reports
    counts = {v: sum(r.verdict == v for r in reports) for v in RANK}
    return json.dumps({
        "reports": [r.to_dict() for r in reports],
        "counts": counts,
        "distinct": len({r.fingerprints["structural"] for r in reports}),
        "clusters": _clusters(reports),
        "truncated": truncated,
    })


def export_fingerprints() -> str:
    """Labelling template (TOML) for every non-LOW fingerprint of the last run."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "fingerprints.toml"
        export_toml(_state["reports"], p)
        return p.read_text(encoding="utf-8")
