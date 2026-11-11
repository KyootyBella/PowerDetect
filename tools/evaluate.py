"""Measure detection quality deterministically.

    uv run --group data python tools/evaluate.py            # summary
    uv run --group data python tools/evaluate.py --misses   # also write data/eval_misses.txt

Attack set : Atomic Red Team PowerShell tests + LOLBAS commands (data/sources, see
             tools/build_fingerprint_db.py fetch). Detected = verdict >= SUSPICIOUS
             from the RULES ALONE (no fingerprint DB, so this measures real detection).
Benign set : tests/data/benign.txt      - every line must be LOW
             tests/data/borderline.txt  - must never be MALICIOUS
"""
from __future__ import annotations

import argparse
import base64
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from powerdetect import Rules, analyze  # noqa: E402
from powerdetect.engine import RANK  # noqa: E402

CONTEXT = {"discovery", "reconnaissance"}


def load_corpus(path: Path) -> list[str]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if line.startswith("ENC: "):
            b = base64.b64encode(line[5:].encode("utf-16-le")).decode()
            line = ("powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass "
                    f"-WindowStyle Hidden -EncodedCommand {b}")
        out.append(line)
    return out


def evaluate(rules: Rules, write_misses: bool = False) -> dict:
    from build_fingerprint_db import parse_atomic, parse_lolbas

    res: dict = {}
    by_tactic = defaultdict(Counter)
    misses = []
    for s in parse_atomic():
        if not s.is_powershell:
            continue
        r = analyze(s.command, rules)
        c = by_tactic[s.tactic]
        c["n"] += 1
        c["det"] += RANK[r.verdict] >= 1
        c["mal"] += r.verdict == "MALICIOUS"
        if r.verdict == "LOW" and s.tactic not in CONTEXT:
            misses.append(f"[{s.tactic}] {s.label} (score {r.score})\n    "
                          + " ".join(s.command.split())[:260])
    res["atomic"] = by_tactic

    lol = Counter()
    for s in parse_lolbas():
        r = analyze(s.command, rules)
        lol["n"] += 1
        lol["det"] += RANK[r.verdict] >= 1
        lol["mal"] += r.verdict == "MALICIOUS"
    res["lolbas"] = lol

    fp = []
    for cmd in load_corpus(ROOT / "tests" / "data" / "benign.txt"):
        r = analyze(cmd, rules)
        if r.verdict != "LOW":
            fp.append((r.verdict, r.score, cmd, [h.id for h in r.hits]))
    over = []
    for cmd in load_corpus(ROOT / "tests" / "data" / "borderline.txt"):
        r = analyze(cmd, rules)
        if r.verdict == "MALICIOUS":
            over.append((r.verdict, r.score, cmd, [h.id for h in r.hits]))
    res["benign_fp"], res["borderline_over"] = fp, over
    res["benign_n"] = len(load_corpus(ROOT / "tests" / "data" / "benign.txt"))

    # same corpora WITH the generated fingerprint DB: it must not create FPs either
    db_path = ROOT / "data" / "known_fingerprints.toml"
    res["db_fp"] = []
    if db_path.exists():
        from powerdetect.fingerprint import FingerprintDB
        db = FingerprintDB(db_path)
        for name, worst in (("benign.txt", "LOW"), ("borderline.txt", "SUSPICIOUS")):
            for cmd in load_corpus(ROOT / "tests" / "data" / name):
                r = analyze(cmd, rules, db)
                if RANK[r.verdict] > RANK[worst]:
                    res["db_fp"].append((name, r.verdict, cmd, [k["label"][:60] for k in r.known]))
    if write_misses:
        (ROOT / "data" / "eval_misses.txt").write_text("\n".join(misses) + "\n", encoding="utf-8")
    return res


def report(res: dict) -> str:
    L = ["Atomic Red Team PowerShell tests (rules only, no fingerprint DB):",
         f"  {'tactic':<22}{'n':>5}{'detected':>10}{'rate':>8}{'malicious':>11}"]
    tot = Counter()
    for t, c in sorted(res["atomic"].items()):
        L.append(f"  {t:<22}{c['n']:>5}{c['det']:>10}{100 * c['det'] / c['n']:>7.1f}%{c['mal']:>11}")
        if t not in CONTEXT:
            tot.update(c)
    L.append(f"  {'ALL (excl. discovery)':<22}{tot['n']:>5}{tot['det']:>10}"
             f"{100 * tot['det'] / max(tot['n'], 1):>7.1f}%{tot['mal']:>11}")
    lol = res["lolbas"]
    L.append(f"LOLBAS commands: {lol['det']}/{lol['n']} detected "
             f"({100 * lol['det'] / max(lol['n'], 1):.1f}%), {lol['mal']} malicious")
    L.append(f"Benign corpus: {len(res['benign_fp'])} false positive(s) of {res['benign_n']}")
    for v, s, cmd, ids in res["benign_fp"]:
        L.append(f"  FP {v} {s}: {cmd[:110]}  {ids}")
    L.append(f"Borderline corpus: {len(res['borderline_over'])} rated MALICIOUS (must be 0)")
    for v, s, cmd, ids in res["borderline_over"]:
        L.append(f"  OVER {v} {s}: {cmd[:110]}  {ids}")
    L.append(f"With fingerprint DB: {len(res['db_fp'])} corpus line(s) escalated too far (must be 0)")
    for name, v, cmd, labels in res["db_fp"]:
        L.append(f"  DB-FP {name} {v}: {cmd[:100]}  {labels}")
    return "\n".join(L)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser()
    p.add_argument("--rules")
    p.add_argument("--misses", action="store_true")
    a = p.parse_args()
    print(report(evaluate(Rules(a.rules) if a.rules else Rules(), a.misses)))


if __name__ == "__main__":
    main()
