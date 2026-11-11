"""Build a known-fingerprint database from public attack datasets.

    uv run --group data python tools/build_fingerprint_db.py fetch   # download sources
    uv run --group data python tools/build_fingerprint_db.py build   # parse + fingerprint

Sources (downloaded into data/sources/, parsed as text only - NOTHING is executed):
  atomic   Atomic Red Team index.yaml            (MIT)        MITRE-labelled attack tests
  lolbas   LOLBAS yml/*                          (GPL-3.0)    LOLBin abuse commands
  revoke   Revoke-Obfuscation labelled CSVs      (Apache-2.0) obfuscation corpus labels

Outputs:
  data/known_fingerprints.toml   use with:  powerdetect --known data/known_fingerprints.toml
  data/build_report.md           stats, detection gaps, deobfuscation robustness

Verdict policy (deterministic):
  * every entry gets a label (source, MITRE technique, test name)
  * MALICIOUS   - only if PowerDetect's rules already score that command MALICIOUS
  * SUSPICIOUS  - any other known attack command (raises a LOW match so it surfaces);
                  the DB never escalates beyond the rules' own conclusion, because
                  legitimate commands can share a structure with an attack test
  * no verdict  - context only, when every sample behind the fingerprint is
                  discovery / reconnaissance (whoami, net user ... are normal admin work)
  * skeletons shorter than MIN_SKELETON characters are skipped as too generic
  * the engine only ever RAISES a verdict from these entries; only an explicit
    verdict = "LOW" entry (your own allow-list) lowers one
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import re
import sys
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from powerdetect import Rules, analyze, cmdline  # noqa: E402
from powerdetect.engine import RANK  # noqa: E402

DATA = ROOT / "data"
SRC = DATA / "sources"
UA = {"User-Agent": "PowerDetect-db-builder"}
MIN_SKELETON = 25
MAX_TESTS = 25

ATOMIC_URL = ("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/"
              "atomics/Indexes/index.yaml")
REVOKE_API = "https://api.github.com/repos/danielbohannon/Revoke-Obfuscation/contents/DataScience"
LOLBAS_API = "https://api.github.com/repos/LOLBAS-Project/LOLBAS/git/trees/master?recursive=1"
LOLBAS_RAW = "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/"


# ---------------------------------------------------------------- fetch
def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 - fixed https URLs
        return r.read()


def _save(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def fetch(sources: list[str]) -> None:
    if "atomic" in sources:
        print("atomic: index.yaml ...", flush=True)
        _save(SRC / "atomic" / "index.yaml", _get(ATOMIC_URL))
    if "revoke" in sources:
        for item in json.loads(_get(REVOKE_API)):
            if item["type"] == "file" and item["name"].endswith(".csv"):
                print(f"revoke: {item['name']} ...", flush=True)
                _save(SRC / "revoke" / item["name"], _get(item["download_url"]))
    if "lolbas" in sources:
        tree = json.loads(_get(LOLBAS_API))["tree"]
        files = [t["path"] for t in tree if t["type"] == "blob"
                 and t["path"].startswith("yml/") and t["path"].endswith((".yml", ".yaml"))]
        print(f"lolbas: {len(files)} yml files ...", flush=True)
        for p in files:
            _save(SRC / "lolbas" / p, _get(LOLBAS_RAW + p))
    # record hashes so a build can be traced back to exact inputs
    manifest = {str(p.relative_to(SRC)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(SRC.rglob("*")) if p.is_file() and p.name != "MANIFEST.json"}
    (SRC / "MANIFEST.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print(f"done: {len(manifest)} file(s) in {SRC}")


# ---------------------------------------------------------------- parse
@dataclass
class Sample:
    source: str
    label: str
    mitre: str
    command: str
    is_powershell: bool
    tactic: str = ""


CONTEXT_ONLY_TACTICS = {"discovery", "reconnaissance"}


_ARG = re.compile(r"#\{(\w+)\}")


def parse_atomic() -> list[Sample]:
    import yaml
    path = SRC / "atomic" / "index.yaml"
    if not path.exists():
        return []
    doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    out = []
    for tactic, techniques in sorted((doc or {}).items()):
        for tid, body in sorted((techniques or {}).items()):
            for test in (body or {}).get("atomic_tests") or []:
                if "windows" not in (test.get("supported_platforms") or []):
                    continue
                ex = test.get("executor") or {}
                cmd = ex.get("command")
                kind = (ex.get("name") or "").lower()
                if not cmd or kind not in ("powershell", "command_prompt"):
                    continue
                defaults = {k: str((v or {}).get("default", ""))
                            for k, v in (test.get("input_arguments") or {}).items()}
                cmd = _ARG.sub(lambda m: defaults.get(m.group(1), m.group(0)), cmd).strip()
                is_ps = kind == "powershell" or bool(re.search(r"(?i)\b(powershell|pwsh)\b", cmd))
                out.append(Sample("atomic", f"{tid} {test.get('name', '').strip()} [{tactic}]",
                                  tid, cmd, is_ps, str(tactic).lower()))
    return out


def parse_lolbas() -> list[Sample]:
    import yaml
    out = []
    for p in sorted((SRC / "lolbas").rglob("*.y*ml")):
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8", errors="replace")) or {}
        except yaml.YAMLError:
            continue
        name = doc.get("Name", p.stem)
        for c in doc.get("Commands") or []:
            cmd = (c or {}).get("Command")
            if not cmd:
                continue
            cmd = str(cmd).strip()
            out.append(Sample("lolbas", f"{c.get('MitreID', '')} {name}: {c.get('Category', '')} - "
                                        f"{str(c.get('Description', '')).strip()[:80]}",
                              str(c.get("MitreID", "")), cmd,
                              bool(re.search(r"(?i)\b(powershell|pwsh)\b", cmd)),
                              str(c.get("Category", "")).lower()))
    return out


def parse_revoke() -> tuple[list[Sample], str]:
    """The Revoke-Obfuscation CSVs are (Path, Label) pairs pointing into a
    separate corpus that is not in the repo, so they contain no script text.
    Only a CSV with a 'Content'/'Script' column would be usable; report format."""
    out, notes = [], []
    for p in sorted((SRC / "revoke").glob("*.csv")):
        text = p.read_text(encoding="utf-8-sig", errors="replace")
        rows = list(csv.DictReader(io.StringIO(text)))
        cols = list(rows[0].keys()) if rows else []
        notes.append(f"{p.name}: {len(rows)} rows, columns {cols}")
        col = next((c for c in cols if c.lower() in ("content", "script", "scriptcontent")), None)
        if not col:
            continue
        for r in rows:
            if str(r.get("Label", "")).strip() in ("1", "True", "true") and r.get(col):
                out.append(Sample("revoke", f"Revoke-Obfuscation obfuscated sample ({p.stem})",
                                  "T1027", r[col], True))
    if notes and not out:
        notes.append("-> no script text in these CSVs (paths only); source contributes 0 samples")
    return out, "\n".join(notes)


# ---------------------------------------------------------------- variants
_LIT = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"`$]|`.)*\"")
_WORD = re.compile(r"(?<![\w$`.-])([A-Za-z]{2,}-[A-Za-z]{3,}|[A-Za-z]{6,})(?![\w`])")
_SAFE_TICK = set("cdghijklmopqswxyzCDGHIJKLMOPQSWXYZ")  # never creates an escape sequence


def _outside_literals(s: str, fn) -> str:
    out, last = [], 0
    for m in _LIT.finditer(s):
        out.append(fn(s[last:m.start()])); out.append(m.group(0)); last = m.end()
    out.append(fn(s[last:]))
    return "".join(out)


def v_ticks(s: str) -> str:
    def word(m):
        w = m.group(1)
        return "".join(("`" + c) if i % 3 == 2 and c in _SAFE_TICK else c for i, c in enumerate(w))
    return _outside_literals(s, lambda seg: _WORD.sub(word, seg))


def v_concat(s: str) -> str:
    def lit(m):
        t = m.group(0)
        if not t.startswith("'") or len(t) < 6 or "''" in t:
            return t
        body = t[1:-1]
        mid = len(body) // 2
        return f"('{body[:mid]}'+'{body[mid:]}')"
    return _LIT.sub(lit, s)


def v_case(s: str) -> str:
    return _outside_literals(s, lambda seg: "".join(
        c.upper() if i % 2 else c.lower() for i, c in enumerate(seg)))


def v_encoded(s: str) -> str:
    return "powershell.exe -NoP -W Hidden -Enc " + base64.b64encode(s.encode("utf-16-le")).decode()


VARIANTS = {"ticks": v_ticks, "concat": v_concat, "case": v_case, "encoded": v_encoded}


# ---------------------------------------------------------------- build
@dataclass
class Entry:
    value: str
    labels: list[str] = field(default_factory=list)
    mitre: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    rules_verdict: str = "LOW"    # highest verdict the rules alone gave any sample
    attack_tactic: bool = False   # at least one sample outside discovery/recon
    example: str = ""

    @property
    def verdict(self) -> str | None:
        # never escalate beyond what the rules concluded for the same structure;
        # the DB only lifts LOW attack commands to SUSPICIOUS so they surface
        if self.rules_verdict == "MALICIOUS":
            return "MALICIOUS"
        return "SUSPICIOUS" if self.attack_tactic or self.rules_verdict == "SUSPICIOUS" else None

    @property
    def label(self) -> str:
        if len(self.labels) == 1:
            return self.labels[0]
        techs = ", ".join(sorted(self.mitre)[:4]) + (" ..." if len(self.mitre) > 4 else "")
        return f"Shared pattern in {len(self.labels)} attack tests ({techs}), e.g. {self.labels[0]}"


def _toml_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)  # JSON string == valid TOML basic string


def build() -> None:
    rules = Rules()
    samples = parse_atomic() + parse_lolbas()
    revoke, revoke_notes = parse_revoke()
    samples += revoke
    if not samples:
        sys.exit("no source data found - run the 'fetch' step first")

    entries: dict[str, Entry] = {}
    stats = Counter()
    by_source = defaultdict(Counter)
    gaps: list[tuple[Sample, int]] = []
    robust = defaultdict(Counter)
    mismatches: list[str] = []

    for s in samples:
        r = analyze(s.command, rules)
        by_source[s.source][r.verdict] += 1
        if s.is_powershell and r.verdict == "LOW":
            gaps.append((s, r.score))
        fp = r.fingerprints["structural"]
        if len(r.skeleton) < MIN_SKELETON:
            stats["skipped_generic"] += 1
            continue
        e = entries.setdefault(fp, Entry(fp, example=" ".join(s.command.split())[:160]))
        if s.label not in e.labels:
            e.labels.append(s.label)
        if s.mitre:
            e.mitre.add(s.mitre)
        e.sources.add(s.source)
        if RANK[r.verdict] > RANK[e.rules_verdict]:
            e.rules_verdict = r.verdict
        if s.tactic not in CONTEXT_ONLY_TACTICS:
            e.attack_tactic = True

        if s.is_powershell and s.source == "atomic":
            # obfuscate only the script part, as an attacker would (the host
            # flags never enter the skeleton, so fingerprints stay comparable)
            script = cmdline.parse(s.command).script or s.command
            for name, fn in VARIANTS.items():
                v = analyze(fn(script), rules)
                key = "payload" if name == "encoded" else "structural"
                ok = v.fingerprints[key] == r.fingerprints[key]
                robust[name]["same" if ok else "diff"] += 1
                if not ok and len(mismatches) < 300:
                    mismatches.append(f"[{name}] {s.label}\n    {' '.join(s.command.split())[:200]}")

    # ---- write database (sorted -> byte-identical output for identical inputs)
    lines = ["# PowerDetect known fingerprints - generated by tools/build_fingerprint_db.py",
             "# Do not edit by hand; put your own labels in a separate --known file.", ""]
    for fp in sorted(entries):
        e = entries[fp]
        lines.append(f"# example: {e.example}")
        lines.append("[[fingerprint]]")
        lines.append('type = "structural"')
        lines.append(f'value = "{fp}"')
        lines.append(f"label = {_toml_str(e.label)}")
        lines.append("tests = [" + ", ".join(_toml_str(l) for l in e.labels[:MAX_TESTS])
                     + (f", {_toml_str(f'... +{len(e.labels) - MAX_TESTS} more')}"
                        if len(e.labels) > MAX_TESTS else "") + "]")
        lines.append(f"mitre = {_toml_str(', '.join(sorted(e.mitre)))}")
        lines.append(f"source = {_toml_str(', '.join(sorted(e.sources)))}")
        if e.verdict:
            lines.append(f'verdict = "{e.verdict}"')
        lines.append("")
    db_path = DATA / "known_fingerprints.toml"
    db_path.write_text("\n".join(lines), encoding="utf-8")

    # ---- report
    vc = Counter(e.verdict or "context-only" for e in entries.values())
    n_mal = vc["MALICIOUS"]
    R = ["# Fingerprint DB build report", "",
         f"- samples parsed: **{len(samples)}**",
         f"- fingerprints written: **{len(entries)}** (MALICIOUS {vc['MALICIOUS']}, "
         f"SUSPICIOUS {vc['SUSPICIOUS']}, context-only {vc['context-only']})",
         f"- fingerprints shared by more than one test: "
         f"{sum(1 for e in entries.values() if len(e.labels) > 1)}",
         f"- skipped as too generic (skeleton < {MIN_SKELETON} chars): {stats['skipped_generic']}", "",
         "## Verdicts per source (PowerDetect score alone, before the DB)", "",
         "| source | LOW | SUSPICIOUS | MALICIOUS |", "|---|---|---|---|"]
    for src, c in sorted(by_source.items()):
        R.append(f"| {src} | {c['LOW']} | {c['SUSPICIOUS']} | {c['MALICIOUS']} |")
    R += ["", "## Deobfuscation robustness (Atomic PowerShell tests)", "",
          "Each test is re-obfuscated deterministically; the fingerprint should not change.", "",
          "| variant | same fingerprint | different | rate |", "|---|---|---|---|"]
    for name in VARIANTS:
        c = robust[name]
        tot = c["same"] + c["diff"]
        R.append(f"| {name} | {c['same']} | {c['diff']} | {100 * c['same'] / tot:.1f}% |" if tot
                 else f"| {name} | 0 | 0 | - |")
    R += ["", f"## Detection gaps: PowerShell samples scored LOW ({len(gaps)})", "",
          "These are known attack commands that the rules alone do not flag. "
          "Candidates for new rules (the DB still labels them).", ""]
    tech = Counter(s.mitre for s, _ in gaps)
    R += [f"- {t or '?'}: {n}" for t, n in tech.most_common(40)]
    R += ["", "## Revoke-Obfuscation CSV format", "", "```", revoke_notes or "(not downloaded)", "```",
          f"usable inline samples: {len(revoke)}"]
    (DATA / "build_report.md").write_text("\n".join(R) + "\n", encoding="utf-8")
    (DATA / "variant_mismatches.txt").write_text("\n".join(mismatches) + "\n", encoding="utf-8")
    (DATA / "detection_gaps.txt").write_text("\n".join(
        f"[{s.mitre}] {s.label} (score {sc})\n    {' '.join(s.command.split())[:300]}"
        for s, sc in gaps) + "\n", encoding="utf-8")
    print(f"{len(samples)} samples -> {len(entries)} fingerprints "
          f"(MALICIOUS {vc['MALICIOUS']}, SUSPICIOUS {vc['SUSPICIOUS']}, "
          f"context-only {vc['context-only']}) -> {db_path}")
    print(f"report: {DATA / 'build_report.md'}")


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("step", choices=["fetch", "build", "all"])
    p.add_argument("--sources", default="atomic,lolbas,revoke")
    a = p.parse_args()
    if a.step in ("fetch", "all"):
        fetch(a.sources.split(","))
    if a.step in ("build", "all"):
        build()


if __name__ == "__main__":
    main()
