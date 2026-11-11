"""Assemble the static website into docs/ (ready for GitHub Pages or any static host).

    uv run python tools/build_site.py            # with the fingerprint DB if data/ has one
    uv run python tools/build_site.py --no-db    # engine and rules only

The site runs the real powerdetect package in the browser via Pyodide, so its
verdicts are identical to the CLI. Output is deterministic (no timestamps).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from powerdetect.fingerprint import toml_files, toml_str  # noqa: E402
WEB = ROOT / "web"
PKG = ROOT / "powerdetect"
DB = ROOT / "data" / "known_fingerprints.toml"
COMMUNITY = ROOT / "data" / "community"
OUT = ROOT / "docs"
PKG_FILES = ["__init__.py", "cmdline.py", "deobfuscate.py", "engine.py", "fingerprint.py",
             "statements.py", "webapi.py", "rules.toml"]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--no-db", action="store_true", help="do not bundle the fingerprint DB")
    a = p.parse_args()

    if OUT.exists():
        if not (OUT / "py" / "manifest.json").exists():
            sys.exit(f"{OUT} exists but was not created by this script - refusing to delete it")
        shutil.rmtree(OUT)
    (OUT / "py" / "powerdetect").mkdir(parents=True)

    for f in sorted(WEB.iterdir()):
        if f.is_file():
            shutil.copy2(f, OUT / f.name)
    (OUT / ".nojekyll").write_text("", encoding="utf-8")  # serve files as-is on GitHub Pages

    # bundled Python runtime, verified against the pinned hashes before copying
    sys.path.insert(0, str(Path(__file__).parent))
    from fetch_pyodide import FILES as RT_FILES, OUT as RT_DIR, PINNED  # noqa: E402
    (OUT / "pyodide").mkdir()
    for name in RT_FILES:
        src = RT_DIR / name
        if not src.exists():
            shutil.rmtree(OUT)
            sys.exit(f"missing {src} - run: uv run python tools/fetch_pyodide.py")
        if hashlib.sha256(src.read_bytes()).hexdigest() != PINNED[name]:
            shutil.rmtree(OUT)
            sys.exit(f"{src} does not match its pinned hash - re-run tools/fetch_pyodide.py")
        shutil.copy2(src, OUT / "pyodide" / name)

    files = []
    for name in PKG_FILES:
        shutil.copy2(PKG / name, OUT / "py" / "powerdetect" / name)
        files.append(f"powerdetect/{name}")

    db_name = None
    community = toml_files(COMMUNITY) if COMMUNITY.is_dir() else []
    if (DB.exists() or community) and not a.no_db:
        # drop the '# example:' comments (raw attack commands) - only hashes and labels ship
        lines = [l for l in DB.read_text(encoding="utf-8").splitlines()
                 if not l.startswith("# example:")] if DB.exists() else []
        # contributed entries: keep only what matching needs (no `sample` command lines)
        for f in community:
            for e in tomllib.loads(f.read_text(encoding="utf-8")).get("fingerprint", []):
                lines += ["", f"# community: {f.name}", "[[fingerprint]]",
                          f"type = {toml_str(e['type'])}", f"value = {toml_str(e['value'])}",
                          f"label = {toml_str(e['label'])}", f"verdict = {toml_str(e['verdict'])}",
                          'source = "community"']
        text = "\n".join(lines) + "\n"
        tomllib.loads(text)  # validate
        (OUT / "py" / "known_fingerprints.toml").write_text(text, encoding="utf-8")
        db_name = "known_fingerprints.toml"
        files.append(db_name)

    h = hashlib.sha256()
    for rel in files:
        h.update(rel.encode())
        h.update((OUT / "py" / rel).read_bytes())
    for f in sorted(OUT.glob("*.*")):
        h.update(f.read_bytes())
    version = h.hexdigest()[:12]
    manifest = {"version": version, "files": files, "db": db_name}
    (OUT / "py" / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")

    size = sum(f.stat().st_size for f in OUT.rglob("*") if f.is_file())
    print(f"site built in {OUT} ({size / 1024:.0f} KB, build {version}, "
          f"fingerprint DB {'included' if db_name else 'not included'})")


if __name__ == "__main__":
    main()
