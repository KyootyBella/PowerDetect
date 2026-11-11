# Fingerprint DB build report

- samples parsed: **2173**
- fingerprints written: **1587** (MALICIOUS 299, SUSPICIOUS 1172, context-only 116)
- fingerprints shared by more than one test: 341
- skipped as too generic (skeleton < 25 chars): 172

## Verdicts per source (PowerDetect score alone, before the DB)

| source | LOW | SUSPICIOUS | MALICIOUS |
|---|---|---|---|
| atomic | 826 | 485 | 372 |
| lolbas | 348 | 121 | 21 |

## Deobfuscation robustness (Atomic PowerShell tests)

Each test is re-obfuscated deterministically; the fingerprint should not change.

| variant | same fingerprint | different | rate |
|---|---|---|---|
| ticks | 952 | 0 | 100.0% |
| concat | 940 | 12 | 98.7% |
| case | 938 | 14 | 98.5% |
| encoded | 952 | 0 | 100.0% |

## Detection gaps: PowerShell samples scored LOW (418)

These are known attack commands that the rules alone do not flag. Candidates for new rules (the DB still labels them).

- T1098: 18
- T1205.002: 12
- T1112: 12
- T1685: 12
- T1055: 12
- T1218: 10
- T1027.017: 9
- T1087.002: 8
- T1127.003: 8
- T1547.001: 8
- T1134.004: 8
- T1218.004: 7
- T1105: 6
- T1018: 6
- T1518.001: 6
- T1218.005: 6
- T1046: 5
- T1069.002: 5
- T1082: 5
- T1653: 5
- T1218.001: 5
- T1219: 4
- T1685.003: 4
- T1083: 4
- T1497.001: 4
- T1059.001: 4
- T1543.003: 4
- T1546: 4
- T1546.015: 4
- T1546.018: 4
- T1055.012: 4
- T1027: 4
- T1070.003: 4
- T1218.007: 4
- T1216: 4
- T1071.004: 3
- T1553.005: 3
- T1686: 3
- T1016.001: 3
- T1033: 3

## Revoke-Obfuscation CSV format

```
GithubGist-obfuscation-labeledData.csv: 1734 rows, columns ['Path', 'Label']
InvokeCradleCrafter-obfuscation-labeledData.csv: 200 rows, columns ['Path', 'Label']
InvokeObfuscation-obfuscation-labeledData.csv: 3216 rows, columns ['Path', 'Label']
IseSteroids-obfuscation-labeledData.csv: 788 rows, columns ['Path', 'Label']
PoshCode-obfuscation-labeledData.csv: 3404 rows, columns ['Path', 'Label']
TechNet-obfuscation-labeledData.csv: 1539 rows, columns ['Path', 'Label']
UnderhandedPowerShell-obfuscation-labeledData.csv: 383 rows, columns ['Path', 'Label']
-> no script text in these CSVs (paths only); source contributes 0 samples
```
usable inline samples: 0
