"""The decision engine ("brain").

Pipeline, all deterministic:
  1. parse the host command line (flags, -EncodedCommand)
  2. deobfuscate into layers
  3. match rules        - each rule has an ATT&CK tactic, tags, a weight, a 'why'
  4. obfuscation hits   - every obfuscation technique found becomes an explained hit
  5. combinations       - capability tags that are dangerous TOGETHER (download+execute ...)
  6. kill chain         - bonus when activity spans several ATT&CK tactics
  7. verdict            - score thresholds, raised by critical-rule floors (min_verdict)
  8. attribution        - every rule match traced to the statements that caused it
  9. fingerprints + known-fingerprint DB
 10. explanation        - plain-language assessment built from the above
"""
from __future__ import annotations

import hashlib
import math
import re
import tomllib
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import cmdline, fingerprint
from .deobfuscate import deobfuscate
from .statements import split_statements

DEFAULT_RULES = Path(__file__).with_name("rules.toml")
RANK = {"LOW": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
CONTEXT_TACTICS = {"discovery", "reconnaissance"}


def _max_verdict(*vs: str | None) -> str:
    return max((v for v in vs if v), key=RANK.__getitem__, default="LOW")


@dataclass
class Hit:
    id: str
    name: str
    kind: str                 # rule | obfuscation | combo | killchain
    tactic: str
    mitre: str
    weight: int
    why: str
    evidence: str
    tags: list[str] = field(default_factory=list)
    min_verdict: str | None = None
    fp: str = ""              # known false-positive situations
    statements: list[str] = field(default_factory=list)   # e.g. ["host", "L0#2"]


@dataclass
class Statement:
    layer: int | None      # None = host command-line flags
    source: str
    index: int
    text: str
    rules: list[str]       # rule IDs matched inside this statement

    @property
    def where(self) -> str:
        return "host" if self.layer is None else f"L{self.layer}#{self.index}"


@dataclass
class Report:
    sha256: str
    verdict: str
    score: int
    verdict_reason: str
    assessment: str           # plain-language summary
    tactics: list[str]        # ATT&CK tactics observed, kill-chain order
    host: str | None
    flags: dict
    obfuscation: dict[str, int]
    hits: list[Hit]
    statements: list[Statement]
    fingerprints: dict[str, str]
    skeleton: str
    known: list[dict]
    verdict_source: str       # "score" or "fingerprint-db"
    iocs: dict[str, list[str]]
    entropy: float
    layers: list[dict]
    raw: str
    errors: list[str] = field(default_factory=list)

    @property
    def flagged_statements(self) -> list[Statement]:
        return [s for s in self.statements if s.rules]

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------- rules
class Rules:
    def __init__(self, path: Path | str = DEFAULT_RULES):
        with open(path, "rb") as f:
            cfg = tomllib.load(f)
        self.suspicious = cfg["thresholds"]["suspicious"]
        self.malicious = cfg["thresholds"]["malicious"]
        self.tactics: dict[str, str] = cfg["tactics"]          # key -> display name, in order
        self.tactic_order = {t: i for i, t in enumerate(self.tactics)}
        self.obfuscation: dict[str, dict] = cfg.get("obfuscation", {})
        kc = cfg.get("killchain", {})
        self.kc_min = int(kc.get("min_tactics", 3))
        self.kc_weight = int(kc.get("weight", 15))
        self.kc_step = int(kc.get("step", 10))
        self.kc_why = kc.get("why", "")

        self.rules: list[dict] = []
        for r in cfg.get("rule", []):
            self._check(r, "rule")
            self.rules.append({
                **r,
                "re": re.compile(r["pattern"], re.I),
                "requires_re": [re.compile(p, re.I) for p in r.get("requires", [])],
                "exclude_re": re.compile(r["exclude"], re.I) if r.get("exclude") else None,
                "target": r.get("target", "script"),
                "tags": list(r.get("tags", [])),
            })
        self.combos: list[dict] = []
        for c in cfg.get("combo", []):
            self._check(c, "combo", need_pattern=False)
            self.combos.append({**c, "all_tags": list(c.get("all_tags", [])),
                                "any_tags": list(c.get("any_tags", []))})

        ids = [r["id"] for r in self.rules] + [c["id"] for c in self.combos]
        dup = [i for i, n in Counter(ids).items() if n > 1]
        if dup:
            raise ValueError(f"duplicate rule ids: {dup}")
        self.by_id = {r["id"]: r for r in self.rules}

    def _check(self, r: dict, kind: str, need_pattern: bool = True) -> None:
        rid = r.get("id", "?")
        for k in ("id", "name", "weight", "why", "tactic") + (("pattern",) if need_pattern else ()):
            if k not in r:
                raise ValueError(f"{kind} {rid}: missing '{k}'")
        if r["tactic"] not in self.tactics and r["tactic"] != "multiple":
            raise ValueError(f"{kind} {rid}: unknown tactic {r['tactic']!r}")
        if r.get("min_verdict") and r["min_verdict"] not in RANK:
            raise ValueError(f"{kind} {rid}: bad min_verdict {r['min_verdict']!r}")

    def tactic_name(self, t: str) -> str:
        return self.tactics.get(t, t.replace("-", " ").title())


# ---------------------------------------------------------------- helpers
def shannon(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return round(-sum(v / n * math.log2(v / n) for v in c.values()), 3)


_URL = re.compile(r"https?://[^\s'\"`)<>;|]+", re.I)
_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_PATH = re.compile(r"(?:[a-z]:\\|\\\\|%\w+%\\|\$env:\w+\\?)[^\s'\"`;|<>]+\.(?:exe|dll|ps1|bat|vbs|js|hta|dmp|zip|bin|dat)\b", re.I)
_REG = re.compile(r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+)(?::)?\\[^\s'\"`;|]+", re.I)


def extract_iocs(text: str) -> dict[str, list[str]]:
    urls = sorted(set(u.rstrip(".,") for u in _URL.findall(text)))
    ips = sorted(set(_IP.findall(text)) - {"127.0.0.1", "0.0.0.0"})
    return {"urls": urls, "ips": ips,
            "domains": sorted({re.sub(r"^https?://([^/:]+).*", r"\1", u, flags=re.I).lower()
                               for u in urls} - set(ips)),
            "files": sorted(set(_PATH.findall(text))),
            "registry": sorted(set(_REG.findall(text)))}


def _snip(text: str, m: re.Match, pad: int = 40) -> str:
    a, b = max(0, m.start() - pad), min(len(text), m.end() + pad)
    return re.sub(r"\s+", " ", text[a:b]).strip()[:200]


def _walk_statements(layers, script_hits: list[Hit], rules: Rules) -> list[Statement]:
    """Deterministic run-through: every statement of every layer, in order,
    with the rules whose matches overlap it."""
    order = {h.id: i for i, h in enumerate(script_hits)}
    out: list[Statement] = []
    for li, layer in enumerate(layers):
        spans = split_statements(layer.text)
        found: list[set[str]] = [set() for _ in spans]
        for h in script_hits:
            rx = rules.by_id[h.id]["re"]
            for m in rx.finditer(layer.text):
                if m.end() == m.start():
                    continue
                overlap = [si for si, (a, b) in enumerate(spans) if a < m.end() and m.start() < b]
                # a greedy pattern may run across ';' into neighbouring statements:
                # prefer the statements that match the rule on their own
                alone = [si for si in overlap if rx.search(layer.text[spans[si][0]:spans[si][1]])]
                for si in alone or overlap:
                    found[si].add(h.id)
        for si, (a, b) in enumerate(spans):
            out.append(Statement(li, layer.source, si, layer.text[a:b],
                                 sorted(found[si], key=order.__getitem__)))
    return out


# ---------------------------------------------------------------- analysis
def _match_rules(rules: Rules, flag_text: str, script_text: str) -> list[Hit]:
    hits = []
    for rule in rules.rules:
        is_flag = rule["target"] == "flags"
        text = flag_text if is_flag else script_text
        m = rule["re"].search(text)
        if not m:
            continue
        if any(not rq.search(script_text) for rq in rule["requires_re"]):
            continue
        if rule["exclude_re"] and rule["exclude_re"].search(text):
            continue
        hits.append(Hit(rule["id"], rule["name"], "rule", rule["tactic"], rule.get("mitre", ""),
                        int(rule["weight"]), rule["why"].strip(), _snip(text, m),
                        rule["tags"], rule.get("min_verdict"), rule.get("fp", "").strip()))
    return hits


def _obfuscation_hits(rules: Rules, techniques: dict[str, int]) -> list[Hit]:
    hits = []
    for tech, count in sorted(techniques.items()):
        cfg = rules.obfuscation.get(tech)
        if not cfg:
            continue
        hits.append(Hit(f"OBF-{tech}", cfg.get("name", tech), "obfuscation", "stealth",
                        cfg.get("mitre", "T1027"), int(cfg["weight"]), cfg["why"].strip(),
                        f"seen {count}x while deobfuscating", ["obfuscation"],
                        cfg.get("min_verdict")))
    return hits


def _combo_hits(rules: Rules, base: list[Hit]) -> list[Hit]:
    tags = {t for h in base for t in h.tags}
    out = []
    for c in rules.combos:
        if not set(c["all_tags"]) <= tags:
            continue
        if c["any_tags"] and not tags & set(c["any_tags"]):
            continue
        want = set(c["all_tags"]) | set(c["any_tags"])
        parts = sorted({h.id for h in base if want & set(h.tags)})
        out.append(Hit(c["id"], c["name"], "combo", c["tactic"], c.get("mitre", ""),
                       int(c["weight"]), c["why"].strip(), "built from " + ", ".join(parts),
                       [], c.get("min_verdict"), c.get("fp", "").strip()))
    return out


def _killchain_hit(rules: Rules, base: list[Hit]) -> tuple[Hit | None, list[str]]:
    order = lambda t: rules.tactic_order.get(t, 99)  # noqa: E731
    tactics = sorted({h.tactic for h in base if h.kind in ("rule", "obfuscation")}, key=order)
    # weak context-only signals (weight <= 5) never count towards the kill chain
    attack = sorted({h.tactic for h in base if h.kind in ("rule", "obfuscation") and h.weight > 5
                     and h.tactic not in CONTEXT_TACTICS}, key=order)
    if len(attack) < rules.kc_min:
        return None, tactics
    w = rules.kc_weight + rules.kc_step * (len(attack) - rules.kc_min)
    names = ", ".join(rules.tactic_name(t) for t in attack)
    return Hit("KC", f"Activity spans {len(attack)} ATT&CK tactics", "killchain", "multiple", "",
               w, rules.kc_why.strip(), names), tactics


def _assessment(rules: Rules, verdict: str, score: int, hits: list[Hit], tactics: list[str],
                floor_hits: list[Hit], has_layers: bool) -> tuple[str, str]:
    # verdict reason
    thr = (f"score {score} >= {rules.malicious} (malicious threshold)" if score >= rules.malicious
           else f"score {score} >= {rules.suspicious} (suspicious threshold)" if score >= rules.suspicious
           else f"score {score} is below the suspicious threshold ({rules.suspicious})")
    critical = [h for h in hits if h.min_verdict and RANK[h.min_verdict] >= RANK[verdict] > 0]
    crit_txt = ", ".join(f"{h.id} ({h.name})" for h in critical[:3]) + \
        (f" and {len(critical) - 3} more" if len(critical) > 3 else "")
    if floor_hits:
        top = floor_hits[0]
        reason = (f"critical indicator {top.id} ({top.name}) forces at least {top.min_verdict} "
                  f"on its own; {thr}")
    elif critical:
        reason = f"{thr}; independently confirmed by critical indicator(s) {crit_txt}"
    else:
        reason = thr

    rule_hits = [h for h in hits if h.kind in ("rule", "obfuscation")]
    if not rule_hits:
        return reason, ("No known attack behaviour was found" +
                        (" after deobfuscation" if has_layers else "") +
                        ". LOW is not proof of safety: review the decoded command.")
    by_tactic: dict[str, list[str]] = {}
    for h in sorted(rule_hits, key=lambda h: (rules.tactic_order.get(h.tactic, 99), -h.weight)):
        by_tactic.setdefault(h.tactic, []).append(h.name)
    behaviour = "; ".join(f"{rules.tactic_name(t)}: {', '.join(n[:3])}"
                          + (f" (+{len(n) - 3})" if len(n) > 3 else "")
                          for t, n in by_tactic.items())
    combos = [h.name for h in hits if h.kind == "combo"]
    s = f"Observed behaviour - {behaviour}."
    if combos:
        s += " Dangerous combination: " + "; ".join(combos) + "."
    if verdict == "LOW":
        s += f" These are weak signals on their own (below {rules.suspicious})."
    fps = [h for h in hits if h.fp and h.kind == "rule"]
    if fps and verdict != "MALICIOUS":
        s += " Check the false-positive notes before escalating."
    return reason, s


def analyze(raw: str, rules: Rules | None = None,
            db: fingerprint.FingerprintDB | None = None) -> Report:
    rules = rules or Rules()
    errors: list[str] = []
    pc = cmdline.parse(raw)
    if pc.decode_error:
        errors.append(f"EncodedCommand decode failed: {pc.decode_error}")
    r = deobfuscate(pc.script or raw)

    flag_text = " ".join(f"{k}={v}" if v is not True else k for k, v in sorted(pc.flags.items()))
    if pc.cmd_wrapper:
        flag_text += " cmd_wrapper"
    script_text = r.all_text

    rule_hits = _match_rules(rules, flag_text, script_text)
    base = rule_hits + _obfuscation_hits(rules, r.techniques)
    combos = _combo_hits(rules, base)
    kc, tactics = _killchain_hit(rules, base)
    hits = base + combos + ([kc] if kc else [])
    hits.sort(key=lambda h: (-h.weight, h.id))

    # attribution
    flag_ids = {rr["id"] for rr in rules.rules if rr["target"] == "flags"}
    flag_hits = [h for h in rule_hits if h.id in flag_ids]
    script_hits = sorted((h for h in rule_hits if h.id not in flag_ids), key=lambda h: (-h.weight, h.id))
    statements: list[Statement] = []
    if pc.host:
        statements.append(Statement(None, "host command line", 0,
                                    flag_text.strip() or pc.host, [h.id for h in flag_hits]))
    statements += _walk_statements(r.layers, script_hits, rules)
    where: dict[str, list[str]] = {}
    for s in statements:
        for rid in s.rules:
            where.setdefault(rid, []).append(s.where)
    for h in hits:
        h.statements = where.get(h.id, [])

    # verdict
    score = sum(h.weight for h in hits)
    by_score = ("MALICIOUS" if score >= rules.malicious
                else "SUSPICIOUS" if score >= rules.suspicious else "LOW")
    floor_hits = sorted((h for h in hits if h.min_verdict),
                        key=lambda h: (-RANK[h.min_verdict], -h.weight, h.id))
    floor = floor_hits[0].min_verdict if floor_hits else None
    verdict = _max_verdict(by_score, floor)
    if floor_hits and RANK[floor] <= RANK[by_score]:
        floor_hits = []  # the floor did not change anything; don't claim it did
    reason, assessment = _assessment(rules, verdict, score, hits, tactics, floor_hits,
                                     len(r.layers) > 1 or bool(r.techniques) or pc.encoded)

    fps, skel = fingerprint.compute([l.text for l in r.layers], [h.id for h in hits],
                                    list(r.techniques))
    known, verdict_source = [], "score"
    if db:
        matches = db.match(fps)
        known = [{"type": e.type, "value": e.value, "label": e.label, "verdict": e.verdict}
                 for e in matches]
        labelled = [e.verdict for e in matches if e.verdict]
        if labelled:
            top = _max_verdict(*labelled)
            # a known-bad match can only raise the verdict; an explicit LOW
            # entry (and nothing worse) is an allow-list and lowers it
            new = "LOW" if top == "LOW" else _max_verdict(verdict, top)
            if new != verdict:
                reason += f"; fingerprint DB sets {new} ({matches[0].label[:80]})"
            verdict = new
            verdict_source = "fingerprint-db"

    return Report(
        sha256=hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest(),
        verdict=verdict, score=score, verdict_reason=reason, assessment=assessment,
        tactics=[t for t in tactics], host=pc.host, flags=pc.flags,
        obfuscation=dict(sorted(r.techniques.items())), hits=hits,
        statements=statements, fingerprints=fps, skeleton=skel, known=known,
        verdict_source=verdict_source,
        iocs=extract_iocs(script_text), entropy=shannon(pc.script or raw),
        layers=[{"source": l.source, "text": l.text} for l in r.layers],
        raw=raw, errors=errors)
