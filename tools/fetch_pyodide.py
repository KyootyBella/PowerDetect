"""Download the Pyodide runtime so the website works fully offline.

    uv run python tools/fetch_pyodide.py

Only the five core files the site actually loads are fetched (no packages). Each
file is downloaded from the jsdelivr CDN and verified against the official
GitHub release archive (a second, independent source). The archive is read in
memory, never extracted. Once pinned (PINNED below), every later run verifies
the files against those hashes and refuses anything different.

Output: vendor/pyodide/ (copied into docs/pyodide/ by tools/build_site.py)
"""
from __future__ import annotations

import hashlib
import io
import sys
import tarfile
import urllib.request
from pathlib import Path

VERSION = "0.27.2"
FILES = ["pyodide.js", "pyodide.asm.js", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json"]
CDN = f"https://cdn.jsdelivr.net/pyodide/v{VERSION}/full/"
RELEASE = f"https://github.com/pyodide/pyodide/releases/download/{VERSION}/pyodide-core-{VERSION}.tar.bz2"
OUT = Path(__file__).resolve().parents[1] / "vendor" / "pyodide"
UA = {"User-Agent": "PowerDetect-fetch"}

# sha256 of each file, pinned after the first download was verified against the
# official GitHub release archive (pyodide-core-0.27.2.tar.bz2) on 2026-11-11
PINNED: dict[str, str] = {
    "pyodide.js": "ee1ce9d20fd7d5fc6df64f77751bf635e7a929665f2c33bfdaf84c175a525d52",
    "pyodide.asm.js": "c5bc43242dbdd922b03fd9f9ca22480d37451238686e84cb38499143f81ec75b",
    "pyodide.asm.wasm": "7936ef6019d80723adce4bd86666b84534d071362839f1cf9b2b80bed917c812",
    "python_stdlib.zip": "7a4edf94cc3d937ba29078adb857d1646d9ce064ad93e795645d124e212eb5a1",
    "pyodide-lock.json": "3a3cfb1c0bc02917a1792c1ecdf2b9b484ca406f5d03cb8af4083e97ec7d706a",
}


def get(url: str) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 - fixed https URLs
        return r.read()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    cdn = {}
    for f in FILES:
        print(f"cdn: {f} ...", flush=True)
        cdn[f] = get(CDN + f)

    if PINNED:
        bad = [f for f in FILES if sha(cdn[f]) != PINNED.get(f)]
        if bad:
            sys.exit(f"hash mismatch against pinned values: {bad} - refusing to install")
        print("all files match the pinned hashes")
    else:
        print(f"release: {RELEASE.rsplit('/', 1)[1]} ...", flush=True)
        with tarfile.open(fileobj=io.BytesIO(get(RELEASE)), mode="r:bz2") as tar:
            rel = {}
            for m in tar.getmembers():
                name = m.name.rsplit("/", 1)[-1]
                if m.isfile() and name in FILES:
                    rel[name] = tar.extractfile(m).read()
        missing = [f for f in FILES if f not in rel]
        if missing:
            sys.exit(f"release archive lacks {missing}")
        bad = [f for f in FILES if sha(cdn[f]) != sha(rel[f])]
        if bad:
            sys.exit(f"CDN and GitHub release differ for {bad} - refusing to install")
        print("CDN files are identical to the official GitHub release")

    OUT.mkdir(parents=True, exist_ok=True)
    sums = []
    for f in FILES:
        (OUT / f).write_bytes(cdn[f])
        sums.append(f"{sha(cdn[f])}  {f}")
        print(f"  {sha(cdn[f])}  {len(cdn[f]) / 1048576:6.2f} MB  {f}")
    (OUT / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    (OUT / "VERSION").write_text(VERSION + "\n", encoding="utf-8")
    total = sum(len(b) for b in cdn.values()) / 1048576
    print(f"installed Pyodide {VERSION} into {OUT} ({total:.1f} MB)")


if __name__ == "__main__":
    main()
