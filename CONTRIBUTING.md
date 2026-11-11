# Contributing to PowerDetect

## Contributing fingerprints

A fingerprint lets PowerDetect recognise a command it has seen before, even
when the attacker changes the C2 address, renames variables or re-obfuscates
it. If you've triaged a malicious PowerShell command line, sharing its
fingerprint helps the next analyst who sees it.

### What makes a good contribution

- **Real attacker activity**, such as a loader, stager, ClickFix lure,
  credential theft or a ransomware precursor, ideally with a public report
  describing it.
- **Something specific.** A fingerprint should describe one tool or technique.
  A plain `Get-Process` or a common admin one-liner is not a fingerprint
  anyone wants.
- **Flags only.** Contributions are `SUSPICIOUS` or `MALICIOUS`. Allow-lists
  (`LOW`) depend on your environment, so keep them in your own file (`--known
  my_allowlist.toml`). That way nobody can contribute an entry that silences
  detection for everyone.
- **`structural` or `payload` type.** `behavior` is too broad to share and
  `exact` too narrow.

### 1. Get the fingerprint

On the **website**, paste the command, click **Analyze**, then **Export
fingerprints**. With the **CLI**:

```bash
uv run powerdetect -f command.txt --export-fingerprints contribution.toml
```

The export has one entry per suspicious or malicious command, with the
fingerprint `value`, the `verdict`, suggested `mitre` techniques and the
command as `sample`. Put the command in a file (`-f`) rather than on the
command line; endpoint protection often blocks processes whose arguments look
like attacks.

### 2. Clean the sample

The `sample` is published, so remove anything from your own environment:
internal host names and domains, user names, share names, tenant IDs, and
any real secret or token.

PowerDetect's fingerprint ignores **URLs, IP addresses, file paths, numbers,
long base64 strings and variable names**. Replace those freely and the
fingerprint stays the same. Use documentation values:

| Replace | With |
| --- | --- |
| IP addresses | `192.0.2.10`, `198.51.100.7`, `203.0.113.5` |
| Domains and URLs | `example.com`, `https://cdn.example/a.ps1` |
| User folders | `C:\Users\user\...` |

If you must change something the fingerprint does *not* ignore, such as a
bare host name or a user name inside a string, the fingerprint will change,
and the entry will then match only the cleaned version. In that case,
consider whether the entry is still useful, or skip that command.

### 3. Fill in the entry

Save it as `data/community/<short-name>.toml`, for example
`data/community/clickfix-mshta-2026.toml`. You can put several entries in one
file. Start from [`data/community/_template.toml`](data/community/_template.toml):

```toml
[[fingerprint]]
type = "structural"
value = "1a2b3c4d5e6f7a8b"          # from the export
label = "ClickFix lure: clipboard to iex via mshta"
verdict = "MALICIOUS"               # or SUSPICIOUS
sample = 'powershell -w h -c "..."' # cleaned command line
mitre = "T1204.004, T1059.001"      # optional
reference = "https://..."           # optional, a public write-up
author = "your-github-name"         # optional
```

Write the label for the analyst who will read it at 3 a.m.: name the
tool, family or campaign if you know it, and what it does.

### 4. Check it

```bash
uv run python tools/check_fingerprints.py
```

The checker runs PowerDetect on every `sample` and confirms that the
fingerprint comes out as the `value` you wrote. If you cleaned the sample
after exporting, it tells you the new value. It also rejects:
- entries that would match one of the known-good commands in `tests/data/`,
- duplicate entries,
- `LOW` verdicts,
- unknown fields,
- malformed ATT&CK IDs.

Then run the test suite:

```bash
uv run pytest -q
```

### 5. Open a pull request

Commit only your file in `data/community/` and open a pull request. CI runs
the same checks. In the description, say where the command came from (an
incident, a public report, a sandbox) as far as you are allowed to.

### No git? Open an issue

Open a **Fingerprint contribution** issue and paste the cleaned command, a
label and a verdict. A maintainer computes the fingerprint and adds it.

### Licensing

Contributed fingerprints and samples are published under the MIT license,
like the code. Only submit commands you are allowed to share: nothing from a
confidential incident without permission, and never anything containing
working credentials.

## Contributing rules or code

1. Change `powerdetect/rules.toml` or the code.
2. Run `uv run pytest -q`. Every line of `tests/data/benign.txt` must stay
   LOW, and nothing in `tests/data/borderline.txt` may become MALICIOUS.
3. If you have the attack data downloaded, run
   `uv run --group data python tools/evaluate.py` and mention the before and
   after numbers in the pull request.
4. If you change a rule because of a false positive, add the command that
   caused it to `tests/data/benign.txt` or `borderline.txt`.
