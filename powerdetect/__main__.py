"""CLI.  Exit codes: 0 = LOW, 1 = SUSPICIOUS, 2 = MALICIOUS (highest across inputs), 3 = error."""
from __future__ import annotations

import argparse
import csv
import json
import sys
import textwrap
from collections import defaultdict
from pathlib import Path

from .engine import RANK, Report, Rules, analyze
from .fingerprint import FingerprintDB, export_toml

CMD_COLUMNS = ("ProcessCommandLine", "InitiatingProcessCommandLine", "CommandLine",
               "processCommandLine", "commandLine", "ScriptContent")


def _from_json(obj, out: list[str]) -> None:
    """Walk any Defender alert / Graph security / Advanced Hunting JSON export
    and collect every command-line-ish field."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in CMD_COLUMNS and isinstance(v, str) and v.strip():
                out.append(v)
            else:
                _from_json(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _from_json(v, out)


def collect(args) -> list[str]:
    cmds: list[str] = []
    if args.command:
        cmds.append(args.command)
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8-sig", errors="replace")
        cmds += [text] if args.whole else [l for l in text.splitlines() if l.strip()]
    if args.csv:
        with open(args.csv, newline="", encoding="utf-8-sig", errors="replace") as f:
            for row in csv.DictReader(f):
                for col in CMD_COLUMNS:
                    if row.get(col, "").strip():
                        cmds.append(row[col]); break
    if args.json:
        _from_json(json.loads(Path(args.json).read_text(encoding="utf-8-sig")), cmds)
    if not cmds and not sys.stdin.isatty():
        data = sys.stdin.read()
        cmds += [data] if args.whole else [l for l in data.splitlines() if l.strip()]
    # dedupe, keep order (same command line fires many alerts)
    return list(dict.fromkeys(cmds))


_COLOR = {"MALICIOUS": "\033[91m", "SUSPICIOUS": "\033[93m", "LOW": "\033[92m"}


def _one_line(s: str, n: int) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 3] + "..."


def _wrap(text: str, indent: str, width: int = 100, sub: str | None = None) -> list[str]:
    return textwrap.wrap(" ".join(text.split()), width=width, initial_indent=indent,
                         subsequent_indent=indent if sub is None else sub) or [indent]


_KIND_ORDER = {"rule": 0, "obfuscation": 0, "combo": 1, "killchain": 2}


def render(num: int, rep: Report, verbose: bool, color: bool, rules: Rules) -> str:
    c = (lambda s, v: f"{_COLOR[v]}{s}\033[0m") if color else (lambda s, v: s)
    stmt_text = {s.where: s.text for s in rep.statements}
    src = "  [set by fingerprint DB]" if rep.verdict_source != "score" else ""
    L = ["=" * 78,
         f"[{num}] {c(rep.verdict, rep.verdict)}   score {rep.score}{src}"]
    L += _wrap("Why this verdict: " + rep.verdict_reason, "    ", 100, "      ")
    L.append(f"Command : {_one_line(rep.raw, 300)}")
    if rep.host:
        L.append(f"Host    : {rep.host}  flags: {_one_line(str(rep.flags), 200)}")
    L += _wrap(rep.assessment, "Assessment: ", 100, " " * 12)

    fp = rep.fingerprints
    L.append(f"Fingerprint: structural={fp['structural']} payload={fp['payload']} "
             f"behavior={fp['behavior']}")
    for k in rep.known:
        L.append(f"Known      : {_one_line(k['label'], 160)} ({k['type']} match"
                 + (f", verdict {k['verdict']})" if k["verdict"] else ", context only)"))

    signals = [h for h in rep.hits if h.kind in ("rule", "obfuscation")]
    if signals:
        L.append("Reasons by ATT&CK tactic:")
        by_tactic: dict[str, list] = {}
        for h in sorted(signals, key=lambda h: (rules.tactic_order.get(h.tactic, 99), -h.weight, h.id)):
            by_tactic.setdefault(h.tactic, []).append(h)
        for tactic, hs in by_tactic.items():
            L.append(f"  {rules.tactic_name(tactic)}")
            for h in hs:
                crit = f"  [critical: >= {h.min_verdict}]" if h.min_verdict else ""
                L.append(f"    +{h.weight:<3} {h.id:<10} {h.name}"
                         + (f"  ({h.mitre})" if h.mitre else "") + crit)
                L += _wrap(h.why, "               why: ", 104, " " * 20)
                if h.statements:
                    where = h.statements[0]
                    more = f" (+{len(h.statements) - 1} more)" if len(h.statements) > 1 else ""
                    L.append(f"               seen in [{where}]{more}: "
                             f"{_one_line(stmt_text.get(where, h.evidence), 90)}")
                elif h.kind == "obfuscation":
                    L.append(f"               {h.evidence}")
    logic = [h for h in rep.hits if h.kind in ("combo", "killchain")]
    if logic:
        L.append("Combined evidence:")
        for h in sorted(logic, key=lambda h: (_KIND_ORDER[h.kind], -h.weight, h.id)):
            crit = f"  [critical: >= {h.min_verdict}]" if h.min_verdict else ""
            L.append(f"    +{h.weight:<3} {h.id:<10} {h.name}{crit}")
            L += _wrap(h.why, "               why: ", 104, " " * 20)
            L.append(f"               {_one_line(h.evidence, 100)}")
    fps = [h for h in rep.hits if h.fp]
    if fps and rep.verdict != "LOW":
        L.append("False-positive notes (check before escalating):")
        for h in fps:
            L += _wrap(f"{h.id}: {h.fp}", "  - ", 100, "    ")

    iocs = {k: v for k, v in rep.iocs.items() if v}
    if iocs:
        L.append("IOCs:")
        for k, v in iocs.items():
            L.append(f"  {k}: " + ", ".join(v))
    for e in rep.errors:
        L.append(f"Error   : {e}")

    if verbose:
        L.append("Run-through (every statement, in order; ! = triggered a rule):")
        for s in rep.statements:
            mark = "!" if s.rules else " "
            L.append(f"  {mark} [{s.where}] {_one_line(s.text, 160)}"
                     + (f"   <- {', '.join(s.rules)}" if s.rules else ""))
        L.append("Skeleton (normalized form used for the structural fingerprint):")
        L += ["  " + x for x in rep.skeleton.splitlines()]
        for i, l in enumerate(rep.layers):
            L.append(f"Layer L{i} ({l['source']}):")
            L += ["  " + x for x in l["text"].splitlines()]
    else:
        final = rep.layers[-1]["text"] if rep.layers else ""
        if len(rep.layers) > 1 or final.strip() != rep.raw.strip():
            L.append(f"Deobfuscated (innermost of {len(rep.layers)} layer(s)):")
            L += ["  " + x for x in final[:1500].splitlines()]
    return "\n".join(L)


def summary(reports: list[Report], color: bool) -> str:
    c = (lambda s, v: f"{_COLOR[v]}{s}\033[0m") if color else (lambda s, v: s)
    L = ["=" * 78, "SUMMARY"]
    flagged = [(i, r) for i, r in enumerate(reports, 1) if r.verdict != "LOW"]
    flagged.sort(key=lambda x: (-RANK[x[1].verdict], -x[1].score, x[0]))
    if flagged:
        L.append(f"Possibly malicious commands ({len(flagged)}):")
        for i, r in flagged:
            why = "; ".join(h.name for h in r.hits[:3]) or "no rule hits"
            if r.known:
                why = f"known: {_one_line(r.known[0]['label'], 90)}; " + why
            L.append(f"  [{i}] {c(r.verdict, r.verdict):<10} score {r.score:<4} "
                     f"fp {r.fingerprints['structural']}  {_one_line(r.raw, 70)}")
            L.append(f"        why: {why}")
    else:
        L.append("No suspicious or malicious commands.")

    clusters: dict[str, list[tuple[int, Report]]] = defaultdict(list)
    for i, r in enumerate(reports, 1):
        clusters[r.fingerprints["structural"]].append((i, r))
    groups = [(fp, m) for fp, m in clusters.items()
              if len(m) > 1 or m[0][1].verdict != "LOW"]
    groups.sort(key=lambda g: (-max(RANK[r.verdict] for _, r in g[1]), -len(g[1]), g[0]))
    if groups:
        L.append("Fingerprint clusters (same structure after deobfuscation):")
        for fp, members in groups:
            worst = max((r.verdict for _, r in members), key=RANK.__getitem__)
            label = next((_one_line(r.known[0]["label"], 70) for _, r in members if r.known), "")
            ids = ", ".join(str(i) for i, _ in members[:15]) + (" ..." if len(members) > 15 else "")
            L.append(f"  {fp}  x{len(members):<3} {c(worst, worst):<10} "
                     f"{label + '  ' if label else ''}commands [{ids}]")
            L.append(f"        skeleton: {_one_line(members[0][1].skeleton, 100)}")
    counts = {v: sum(r.verdict == v for r in reports) for v in RANK}
    L.append(f"{len(reports)} command(s), {len(clusters)} distinct fingerprint(s): "
             + ", ".join(f"{k}={v}" for k, v in counts.items()))
    return "\n".join(L)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="powerdetect",
                                description="Deterministic static triage of PowerShell commands.")
    p.add_argument("command", nargs="?", help="command line to analyze (quote it)")
    p.add_argument("-f", "--file", help="text file, one command per line (or a whole script with --whole)")
    p.add_argument("--whole", action="store_true", help="treat file/stdin as a single script")
    p.add_argument("--csv", help="Defender Advanced Hunting CSV export")
    p.add_argument("--json", help="Defender alert / hunting JSON export")
    p.add_argument("--rules", default=None, help="custom rules.toml")
    p.add_argument("--known", action="append", metavar="PATH",
                   help="TOML file or folder of labelled fingerprints (known bad / allow-list); "
                        "repeat to load several")
    p.add_argument("--export-fingerprints", metavar="PATH",
                   help="write a TOML labelling template for all non-LOW fingerprints")
    p.add_argument("-o", "--output", choices=["text", "json", "jsonl"], default="text")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="text output: only print non-LOW commands and the summary")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="full run-through: every statement, skeleton and layer")
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)

    try:
        rules = Rules(a.rules) if a.rules else Rules()
        db = FingerprintDB(*a.known) if a.known else None
        cmds = collect(a)
    except Exception as e:  # noqa: BLE001
        print(f"error: {e}", file=sys.stderr)
        return 3
    if not cmds:
        p.print_help()
        return 3

    reports = [analyze(c, rules, db) for c in cmds]
    if a.output == "json":
        print(json.dumps([r.to_dict() for r in reports], indent=2, ensure_ascii=False))
    elif a.output == "jsonl":
        for r in reports:
            print(json.dumps(r.to_dict(), ensure_ascii=False))
    else:
        color = not a.no_color and sys.stdout.isatty()
        for i, r in enumerate(reports, 1):
            if a.quiet and r.verdict == "LOW":
                continue
            print(render(i, r, a.verbose, color, rules))
        print(summary(reports, color))
    if a.export_fingerprints:
        n = export_toml(reports, a.export_fingerprints)
        print(f"wrote {n} fingerprint(s) to {a.export_fingerprints}", file=sys.stderr)
    return max(RANK[r.verdict] for r in reports)


def main_entry() -> None:
    """Console-script entry point (`powerdetect ...`)."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())


if __name__ == "__main__":
    main_entry()
