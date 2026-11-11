# PowerDetect

Deterministic, static triage of PowerShell command lines for SOC analysts.
You give it the `ProcessCommandLine` from a Defender alert. It decodes and
deobfuscates the command **without running it**, then decides whether the
command is malicious and explains why in plain language. Each reason is mapped
to MITRE ATT&CK and traced to the exact statement that triggered it.

The same input always gives the same output. There is no ML and no network
access at analysis time, and the tool itself has no external dependencies
(Python 3.11+ standard library only).

## How it decides

1. **Parse** (`cmdline.py`): if the command line starts with `powershell` or
   `pwsh` (optionally behind `cmd /c`, with `^` escapes removed), PowerDetect
   resolves abbreviated flags (`-e`, `-enc`, `/ec`, `-w 1`, `-ep b`, `-v 2` …)
   and decodes `-EncodedCommand`. Anything else is analyzed as script text.
2. **Deobfuscate** (`deobfuscate.py`): pure text rewrites, repeated until
   nothing changes:
   - backticks, string concatenation, the `-f` format operator
   - `[char]` codes, `.Replace`/`-replace`, string reversal, `-join`
   - embedded payloads: base64 (with Gzip/Deflate) and nested `powershell -enc`,
     up to 6 layers deep
3. **Rules** (`rules.toml`, 129 rules and 12 combinations): each rule has
   - an ATT&CK tactic and technique,
   - a weight, plus capability tags such as `download`, `inmemory`, `evasion`
     and `persistence`,
   - a plain-language `why`,
   - an `fp` note describing legitimate uses,
   - optionally a `min_verdict`, for critical indicators like an AMSI bypass,
     LSASS dump or shadow-copy deletion.
4. **Obfuscation**: each technique found in step 2 becomes an explained hit of
   its own.
5. **Combinations** (`[[combo]]`): capabilities that are dangerous together.
   For example, download + in-memory execution is a fileless stager,
   disabling defences in the same command that does something else shows
   intent, and decode + execute is a packed loader.
6. **Kill chain**: a bonus when real attack activity spans three or more
   ATT&CK tactics (discovery and weak context signals excluded).
7. **Verdict**: `score >= 70` is MALICIOUS and `>= 30` is SUSPICIOUS, raised to
   the highest `min_verdict` among the hits.
8. **Attribution** (`statements.py`): every layer is split into statements,
   and each rule match is traced to the statement that caused it.
9. **Fingerprints** (`fingerprint.py`) plus an optional known-fingerprint
   database.
10. **Explanation**: the verdict reason, an assessment, reasons grouped by
    ATT&CK tactic, the combined evidence, and false-positive notes.

## Install

The project is managed with [uv](https://docs.astral.sh/uv/). To run it from
the project folder:

```bash
uv sync
```

```bash
uv run powerdetect --help
```

To install `powerdetect` as a command available everywhere, straight from
GitHub:

```bash
uv tool install git+https://github.com/KyootyBella/PowerDetect
```

or from a local checkout:

```bash
uv tool install .
```

## Website (no Python needed)

`web/` holds a static website, built into `docs/`, that runs the same engine in the browser
using [Pyodide](https://pyodide.org) (Python compiled to WebAssembly). It
gives identical verdicts to the CLI, with the same rules and fingerprint
database. Users can:

- paste command lines or a whole script,
- open a Defender Advanced Hunting CSV or alert JSON file,
- read the explained results,
- download the results as JSON, or a fingerprint labelling template.

**Nothing is uploaded, and it works offline.** The Python runtime is bundled
with the site (about 13 MB), so there is no CDN and no external request. The
page's Content-Security-Policy only allows the browser to talk to the site
itself, which means it also works on air-gapped analysis machines. Command
lines are attacker-controlled, so the page renders all report data as escaped
text.

The runtime is Pyodide 0.27.2 (MPL-2.0). To fetch it once:

```bash
uv run python tools/fetch_pyodide.py
```

The script downloads only the five core files the site needs and checks each
one against hashes pinned in the script. Those hashes were taken from the
official GitHub release archive. Any file that doesn't match is refused.

Rebuild the site after changing rules or the database:

```bash
uv run python tools/build_site.py
```

Use `--no-db` to leave out the fingerprint database. The build checks the
runtime against the pinned hashes again before copying it.

Pyodide needs a web server; opening `index.html` from disk won't work. To try
the site locally:

```bash
uv run python -m http.server 8765 --directory docs
```

Then open http://localhost:8765.

`docs/` and `vendor/` are generated, so they are not in the repository.

**Publishing on GitHub Pages:** the workflow in `.github/workflows/pages.yml`
runs the tests, fetches the runtime (refusing it unless the pinned hashes
match), builds the site and deploys it. In the repository settings go to
**Pages** and set **Source** to **GitHub Actions**. The deploy step only runs
on `main` and only while the repository is public.

Any other static host works too: build locally and serve the `docs/` folder.
That includes an internal web server, S3, Azure Static Web Apps, or a USB
stick with any small web server. The largest file (the 9.6 MB `.wasm`) is
well under GitHub Pages' 100 MB per-file limit.

The bundled fingerprint database is derived from Atomic Red Team (MIT) and
LOLBAS (GPL-3.0); see [data/NOTICE.md](data/NOTICE.md).

## Usage

```bash
powerdetect "powershell -nop -w hidden -enc JABjAD0A..."
```

```bash
powerdetect --csv hunting_export.csv -q --known data/known_fingerprints.toml
```

```bash
powerdetect --json alert.json -o jsonl
```

```bash
powerdetect -f suspicious_script.ps1 --whole -v
```

| Option                       | Meaning                                                                                               |
| ---------------------------- | ----------------------------------------------------------------------------------------------------- |
| `--csv`                      | Advanced Hunting export. Reads `ProcessCommandLine`, `InitiatingProcessCommandLine` or `CommandLine`. |
| `--json`                     | Any Defender / Graph Security alert JSON. The whole document is searched for command-line fields.     |
| `-q`                         | Only print non-LOW commands, plus the summary.                                                        |
| `-v`                         | Full run-through: every statement in order, the skeleton, and every layer.                            |
| `-o json\|jsonl`             | Machine-readable output for SOAR, including all hits, explanations and fingerprints.                  |
| `--known FILE`               | Labelled fingerprint database (known attacks, or an allow-list).                                      |
| `--export-fingerprints FILE` | Write a labelling template for every non-LOW fingerprint.                                             |
| `--rules FILE`               | Use a custom rules file.                                                                              |

**Exit codes**: 0 = LOW, 1 = SUSPICIOUS, 2 = MALICIOUS, 3 = error.
Duplicate command lines are analyzed once.

### Reading the output

```
[2] MALICIOUS   score 245
    Why this verdict: score 245 >= 70 (malicious threshold); independently confirmed by critical
      indicator(s) PD-V002 (Microsoft Defender disabled or weakened), PD-D004 (Download executed
      directly in memory) ...
Assessment: Observed behaviour - Execution: Download executed directly in memory, Invoke-Expression
            (runs a string as code); Defense Impairment: Microsoft Defender disabled or weakened,
            Defender exclusion added; ... Dangerous combination: Downloads code and runs it in memory;
            Disables defences and then acts.
Reasons by ATT&CK tactic:
  Defense Impairment
    +50  PD-V002    Microsoft Defender disabled or weakened  (T1562.001)  [critical: >= MALICIOUS]
               why: Turning off Defender protections ... is a standard step right before deploying
                    malware or ransomware.
               seen in [L0#1]: Set-MpPreference -DisableRealtimeMonitoring $true
Combined evidence:
    +25  CB-EVADE-ACT Disables defences and then acts  [critical: >= MALICIOUS]
               why: Weakening security controls in the same command that downloads, executes ...
    +15  KC         Activity spans 3 ATT&CK tactics
False-positive notes (check before escalating):
  - PD-V002B: Database, backup and AV-interop guidance often requires exclusions ...
```

- `L0#1` means layer 0, statement 1. `host` refers to the `powershell.exe`
  flags.
- `[critical: >= X]` marks an indicator that guarantees at least verdict X on
  its own.
- The **SUMMARY** at the end lists every possibly malicious command with its
  top reasons, and groups commands into clusters by fingerprint.

### Pulling the input from Defender (Advanced Hunting KQL)

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
   or ProcessCommandLine has_any ("powershell", "pwsh")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```

For full script content, also query
`DeviceEvents | where ActionType == "PowerShellCommand"` or the AMSI
script-block events, and feed the content with `--whole`.

## Fingerprints

| Fingerprint  | What it hashes                            | Use                                                                     |
| ------------ | ----------------------------------------- | ----------------------------------------------------------------------- |
| `structural` | Normalized skeleton of all layers         | Cluster the same attack across hosts, C2 servers and obfuscation styles |
| `payload`    | Skeleton of the innermost layer           | Match the same payload delivered by different loaders                   |
| `behavior`   | Sorted hit IDs and obfuscation techniques | Group commands that do the same kind of thing                           |
| `exact`      | Deobfuscated text                         | Exact duplicates                                                        |

To build the skeleton, PowerDetect lowercases the text and replaces volatile
values with placeholders: URLs, IPs, numbers, base64, byte arrays and paths.
It also renames variables to `$v1`, `$v2` …, expands aliases, and normalizes
quoting. As a result, `IEX (New-Object Net.WebClient).DownloadString(…)`,
``I`E`X (…)`` and `&('I'+'EX') (…)` all produce the same fingerprint.

### Building the known-fingerprint database from public attack data

```bash
uv run --group data python tools/build_fingerprint_db.py fetch
```

```bash
uv run --group data python tools/build_fingerprint_db.py build
```

`fetch` downloads [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
(MIT), [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) (GPL-3.0) and
the Revoke-Obfuscation label files (Apache-2.0) into `data/sources/`. The
Revoke-Obfuscation files turned out to contain only paths and labels, so they
contribute no samples. **Endpoint protection will flag these files**: add an
exclusion for `data/` or run the tool on an analysis VM.

`build` parses everything as text (nothing is executed) and writes:

- `data/known_fingerprints.toml`: about 1,600 labelled fingerprints. Use it
  with `--known`.
- `data/build_report.md`: statistics, detection gaps, and deobfuscation
  robustness (re-obfuscated variants keep the same fingerprint 98–100% of the
  time).

Verdict policy for the database:

- An entry can only repeat the rules' own verdict. It is MALICIOUS only if the
  rules already say so.
- An attack command the rules score LOW is lifted to SUSPICIOUS, so it
  surfaces.
- Discovery commands get a label only (context).
- A database match can only **raise** a verdict. Only an explicit
  `verdict = "LOW"` entry in your own file lowers one (allow-list).

Keep your own labels in a separate file, for example:

```toml
[[fingerprint]]
type = "structural"
value = "1a2b3c4d5e6f7a8b"
label = "SCCM inventory script"
verdict = "LOW"
```

## Measuring detection quality

```bash
uv run --group data python tools/evaluate.py --misses
```

This is a deterministic evaluation against the downloaded attack data and the
benign corpora in `tests/data/`. The scores below use the **rules only**,
without the fingerprint database:

| Data set                                                              | Coverage        |
| --------------------------------------------------------------------- | --------------- |
| Atomic Red Team PowerShell attacks (842, discovery excluded) detected | **60.8%**       |
| – credential access / execution / exfiltration                        | 89% / 74% / 80% |
| LOLBAS commands detected                                              | 29.0%           |
| Benign admin / SCCM / Intune corpus (132): false positives            | **0**           |
| Borderline corpus (exclusions, admin adds, psexec …): rated MALICIOUS | **0**           |

The remaining misses are mostly test harnesses or "run an unnamed binary",
which have no signal in the command line. The fingerprint database still
labels them when they recur.

The rules are written against generic attacker techniques. None of them
mentions Atomic-specific strings, so these numbers are not inflated by
overfitting to the test data.

## Tuning

Edit `powerdetect/rules.toml`. The header documents every field. Use TOML
literal strings `'...'` for regexes, and write a literal `'` as `\x27`.

After every change, run `uv run pytest -q` and `tools/evaluate.py`. Every line
of `tests/data/benign.txt` must stay LOW, and nothing in `borderline.txt` may
become MALICIOUS.

## Limitations

- Values computed at run time are not resolved: variables built in pieces,
  `-bxor` loops, and `$env:comspec[4,15,25]` slicing.
- LOW means no known attack behaviour was found. It is not proof of safety.
- Vendor bootstrap one-liners (Chocolatey, Scoop) are behaviourally identical
  to download cradles and will be flagged. Allow-list them by fingerprint.
- Fingerprints are only as good as the deobfuscation.

## Tests

```bash
uv run pytest -q
```

The tests use documentation IP ranges and `.example` domains. Defender may
still block processes whose arguments contain sample cradles; feed such
samples through a file (`-f`) instead.

## License

The source code is MIT licensed; see [LICENSE](LICENSE). The generated
fingerprint database is derived from Atomic Red Team (MIT) and LOLBAS
(GPL-3.0) and stays under their terms; see [data/NOTICE.md](data/NOTICE.md).
