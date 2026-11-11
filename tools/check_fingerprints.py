"""Check contributed fingerprint files before they are merged.

    uv run python tools/check_fingerprints.py                      # all of data/community/
    uv run python tools/check_fingerprints.py my_fingerprints.toml # one file

For every entry this re-runs PowerDetect on the entry's `sample` and checks that
the fingerprint it produces is the one in the file, so a reviewer never has to
trust a hash. It also refuses entries that would allow-list anything, that
would fire on the known-good test commands, or that are too broad to share.

Exit code 0 = everything passes, 1 = at least one problem (printed).
"""
from __future__ import annotations

import base64
import functools
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from powerdetect import analyze  # noqa: E402
from powerdetect.fingerprint import FingerprintDB, toml_files  # noqa: E402

COMMUNITY = ROOT / "data" / "community"
GENERATED = ROOT / "data" / "known_fingerprints.toml"
KNOWN_GOOD = [ROOT / "tests" / "data" / "benign.txt", ROOT / "tests" / "data" / "borderline.txt"]

REQUIRED = {"type", "value", "label", "verdict", "sample"}
OPTIONAL = {"mitre", "reference", "author", "notes"}
# Contributions may only flag. Allow-listing (LOW) stays in each user's own file.
VERDICTS = {"SUSPICIOUS", "MALICIOUS"}
# structural / payload survive renamed variables, other C2, other obfuscation.
# behavior (just a set of rule IDs) is too broad to share and exact too narrow.
TYPES = {"structural", "payload"}
_HEX16 = re.compile(r"^[0-9a-f]{16}$")
_MITRE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@functools.cache
def known_good_fingerprints() -> tuple[dict, ...]:
    return tuple(analyze(c).fingerprints for c in known_good_commands())


def known_good_commands() -> list[str]:
    """The benign and borderline regression corpora (same format as the tests)."""
    out = []
    for path in KNOWN_GOOD:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            if line.startswith("ENC: "):
                b64 = base64.b64encode(line[5:].encode("utf-16-le")).decode()
                line = ("powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass "
                        f"-WindowStyle Hidden -EncodedCommand {b64}")
            out.append(line)
    return out


def check(paths: list[Path]) -> tuple[list[str], list[str]]:
    """Returns (problems, notes)."""
    problems: list[str] = []
    notes: list[str] = []
    files = [f for p in paths for f in toml_files(p)]
    if not files:
        notes.append("no contributed fingerprint files found")
        return problems, notes

    generated = {(e.type, e.value) for e in FingerprintDB(GENERATED).entries} if GENERATED.exists() else set()
    good_fps = known_good_fingerprints()
    seen: dict[tuple[str, str], str] = {}

    for f in files:
        try:
            cfg = tomllib.loads(f.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as e:
            problems.append(f"{f.name}: not valid TOML: {e}")
            continue
        extra_top = set(cfg) - {"fingerprint"}
        if extra_top:
            problems.append(f"{f.name}: unexpected top-level keys {sorted(extra_top)}")
        entries = cfg.get("fingerprint", [])
        if not entries:
            problems.append(f"{f.name}: no [[fingerprint]] entries")

        for i, e in enumerate(entries, 1):
            where = f"{f.name} entry {i}"
            missing = REQUIRED - set(e)
            unknown = set(e) - REQUIRED - OPTIONAL
            if missing:
                problems.append(f"{where}: missing {sorted(missing)}")
                continue
            if unknown:
                problems.append(f"{where}: unknown keys {sorted(unknown)} "
                                f"(allowed extras: {sorted(OPTIONAL)})")
            t, v = e["type"], str(e["value"]).lower()
            label, verdict, sample = str(e["label"]).strip(), e["verdict"], str(e["sample"])
            if t not in TYPES:
                problems.append(f"{where}: type {t!r} - use one of {sorted(TYPES)}")
                continue
            if not _HEX16.match(v):
                problems.append(f"{where}: value {v!r} is not a 16-character hex fingerprint")
                continue
            if not label or label.upper().startswith("TODO"):
                problems.append(f"{where}: give it a real label")
            if verdict not in VERDICTS:
                problems.append(f"{where}: verdict {verdict!r} - contributions must be "
                                f"{' or '.join(sorted(VERDICTS))} (keep allow-lists in your own file)")
            for tech in filter(None, (s.strip() for s in str(e.get("mitre", "")).split(","))):
                if not _MITRE.match(tech):
                    problems.append(f"{where}: {tech!r} is not an ATT&CK technique ID like T1059.001")
            ref = e.get("reference")
            if ref is not None and not str(ref).startswith("https://"):
                problems.append(f"{where}: reference must be an https:// link")
            if not sample.strip():
                problems.append(f"{where}: sample is empty")
                continue

            actual = analyze(sample).fingerprints[t]
            if actual != v:
                problems.append(f"{where}: the sample's {t} fingerprint is {actual}, not {v} "
                                f"(did the sample change after export? use {actual})")
            if any(fps[t] == v for fps in good_fps):
                problems.append(f"{where}: matches a known-good command in tests/data - too broad")
            key = (t, v)
            if key in seen:
                problems.append(f"{where}: duplicate of {seen[key]}")
            seen.setdefault(key, where)
            if key in generated:
                notes.append(f"{where}: already in known_fingerprints.toml (fine if the label is better)")
    return problems, notes


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = argv if argv is not None else sys.argv[1:]
    paths = [Path(a) for a in args] or [COMMUNITY]
    problems, notes = check(paths)
    for n in notes:
        print(f"note: {n}")
    for p in problems:
        print(f"problem: {p}")
    print(f"{len(problems)} problem(s)" if problems else f"OK: {len(seen_entries(paths))} fingerprint(s) checked")
    return 1 if problems else 0


def seen_entries(paths: list[Path]) -> list[dict]:
    out = []
    for f in (f for p in paths for f in toml_files(p)):
        try:
            out += tomllib.loads(f.read_text(encoding="utf-8")).get("fingerprint", [])
        except (OSError, tomllib.TOMLDecodeError):
            pass
    return out


if __name__ == "__main__":
    sys.exit(main())
