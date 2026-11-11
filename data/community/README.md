# Community fingerprints

Fingerprints contributed by PowerDetect users, one `.toml` file per
contribution. They are loaded by the website and by
`powerdetect --known data/community`. Start from
[`_template.toml`](_template.toml) and read [CONTRIBUTING.md](../../CONTRIBUTING.md)
first.

Every entry is re-checked automatically: `tools/check_fingerprints.py` runs
PowerDetect on the entry's `sample` and the fingerprint has to come out the
same.

Contributed fingerprints are published under the MIT license, like the
PowerDetect code.
