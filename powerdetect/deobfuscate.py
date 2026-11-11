"""Static, deterministic deobfuscation. Nothing is ever executed: every
transform is a pure text rewrite, applied repeatedly until a fixpoint."""
from __future__ import annotations

import base64
import gzip
import re
import zlib
from dataclasses import dataclass, field

from . import cmdline

MAX_ROUNDS = 25
MAX_DEPTH = 6  # nested encoded layers


@dataclass
class Layer:
    source: str   # how this layer was obtained
    text: str


@dataclass
class DeobResult:
    layers: list[Layer] = field(default_factory=list)
    techniques: dict[str, int] = field(default_factory=dict)  # technique -> count

    def hit(self, name: str, n: int = 1) -> None:
        self.techniques[name] = self.techniques.get(name, 0) + n

    @property
    def final(self) -> str:
        return self.layers[-1].text if self.layers else ""

    @property
    def all_text(self) -> str:
        return "\n".join(l.text for l in self.layers)


# ---------------------------------------------------------------- helpers
_SQ = r"'(?:[^']|'')*'"           # single-quoted literal
_DQ = r'"(?:[^"`$]|`.)*"'          # double-quoted literal with no variable expansion
_LIT = rf"(?:{_SQ}|{_DQ})"


def _unquote(lit: str) -> str:
    if lit.startswith("'"):
        return lit[1:-1].replace("''", "'")
    return lit[1:-1]


def _quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return ok / len(s)


def _try_b64(blob: str) -> bytes | None:
    try:
        b = blob + "=" * (-len(blob) % 4)
        return base64.b64decode(b, validate=True)
    except Exception:  # noqa: BLE001
        return None


def _bytes_to_text(data: bytes) -> str | None:
    for fn in (lambda d: gzip.decompress(d), lambda d: zlib.decompress(d, -15),
               lambda d: zlib.decompress(d)):
        try:
            data = fn(data)
            break
        except Exception:  # noqa: BLE001
            pass
    cands = []
    if len(data) > 1 and data[1::2].count(0) > len(data) // 4:
        cands.append(data.decode("utf-16-le", errors="replace"))
    cands.append(data.decode("utf-8", errors="replace"))
    for t in cands:
        if _printable_ratio(t) > 0.9:
            return t
    return None


# ---------------------------------------------------------------- transforms
def strip_ticks(s: str, r: DeobResult) -> str:
    """Remove PowerShell escape backticks used to break up tokens (I`E`X)."""
    out, inq, i, n = [], False, 0, 0
    while i < len(s):
        c = s[i]
        if c == '"':
            inq = not inq
        if c == "`" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt in "\r\n":  # line continuation
                out.append(c); i += 1; continue
            if inq and nxt in "0abefnrtuv\"`$":
                out.append(c); out.append(nxt); i += 2; continue
            n += 1; i += 1; continue
        out.append(c); i += 1
    if n:
        r.hit("tick-obfuscation", n)
    return "".join(out)


_CONCAT = re.compile(rf"({_LIT})\s*\+\s*({_LIT})")


def fold_concat(s: str, r: DeobResult) -> str:
    def rep(m):
        r.hit("string-concatenation")
        return _quote(_unquote(m.group(1)) + _unquote(m.group(2)))
    return _CONCAT.sub(rep, s)


# ('abc') -> 'abc', but never method-call parens like .Foo('abc') / Foo('abc')
# / .'Foo'('abc') (call on a dynamic member name)
_PAREN_LIT = re.compile(rf"(?<![\w\])}}'\"])\(\s*({_LIT})\s*\)")


def unwrap_parens(s: str, r: DeobResult) -> str:
    return _PAREN_LIT.sub(lambda m: m.group(1), s)


_FMT = re.compile(rf"({_LIT})\s*-f\s*((?:{_LIT})(?:\s*,\s*{_LIT})*)", re.I)


def resolve_format(s: str, r: DeobResult) -> str:
    def rep(m):
        fmt = _unquote(m.group(1))
        args = [_unquote(a) for a in re.findall(_LIT, m.group(2))]
        def sub(mm):
            idx = int(mm.group(1))
            return args[idx] if idx < len(args) else mm.group(0)
        if not re.search(r"\{\d+", fmt):
            return m.group(0)
        r.hit("format-operator")
        return _quote(re.sub(r"\{(\d+)(?:,[^}]*)?(?::[^}]*)?\}", sub, fmt))
    return _FMT.sub(rep, s)


_CHAR = re.compile(r"\[char\]\s*\(?\s*(0x[0-9a-f]+|\d+)\s*\)?", re.I)


def resolve_char(s: str, r: DeobResult) -> str:
    def rep(m):
        v = int(m.group(1), 0)
        if v > 0x10FFFF:
            return m.group(0)
        r.hit("char-codes")
        return _quote(chr(v))
    return _CHAR.sub(rep, s)


_CHARARR = re.compile(
    r"(?:-join\s*)?\(?\s*\[char\[\]\]\s*\(\s*((?:(?:0x[0-9a-f]+|\d+)\s*,\s*)*(?:0x[0-9a-f]+|\d+))\s*\)\s*\)?"
    r"(?:\s*-join\s*(?:''|\"\"))?", re.I)


def resolve_char_array(s: str, r: DeobResult) -> str:
    def rep(m):
        nums = [int(x, 0) for x in re.split(r"\s*,\s*", m.group(1).strip())]
        if any(n > 0x10FFFF for n in nums):
            return m.group(0)
        r.hit("char-codes")
        return _quote("".join(chr(n) for n in nums))
    return _CHARARR.sub(rep, s)


_JOIN = re.compile(rf"-join\s*\(\s*((?:{_LIT})(?:\s*,\s*{_LIT})*)\s*\)", re.I)


def resolve_join(s: str, r: DeobResult) -> str:
    def rep(m):
        r.hit("string-concatenation")
        return _quote("".join(_unquote(a) for a in re.findall(_LIT, m.group(1))))
    return _JOIN.sub(rep, s)


_REPLACE_M = re.compile(rf"({_LIT})\s*\.replace\s*\(\s*({_LIT})\s*,\s*({_LIT})\s*\)", re.I)
_REPLACE_OP = re.compile(rf"({_LIT})\s*-c?replace\s*({_LIT})\s*,\s*({_LIT})", re.I)


def resolve_replace(s: str, r: DeobResult) -> str:
    def rep_m(m):
        r.hit("string-replace")
        return _quote(_unquote(m.group(1)).replace(_unquote(m.group(2)), _unquote(m.group(3))))

    def rep_op(m):
        try:
            # PowerShell -replace is regex based and case-insensitive by default
            out = re.sub(_unquote(m.group(2)), _unquote(m.group(3)).replace("$", "\\"),
                         _unquote(m.group(1)), flags=re.I)
        except re.error:
            return m.group(0)
        r.hit("string-replace")
        return _quote(out)
    s = _REPLACE_M.sub(rep_m, s)
    return _REPLACE_OP.sub(rep_op, s)


# 'xei'[-1..-3] -join ''   /   -join 'xei'[-1..-3]   (string reversal)
_REVERSE = re.compile(
    rf"(?:-join\s*)?\(?\s*({_LIT})\s*\[\s*-1\s*\.\.\s*-\s*\(?\s*(?:\d+|{_LIT}\.length|\$\w+\.length)\s*\)?\s*\]\s*\)?(?:\s*-join\s*(?:''|\"\"))?",
    re.I)


def resolve_reverse(s: str, r: DeobResult) -> str:
    def rep(m):
        r.hit("string-reversal")
        return _quote(_unquote(m.group(1))[::-1])
    return _REVERSE.sub(rep, s)


TRANSFORMS = [strip_ticks, resolve_char_array, resolve_char, resolve_format,
              resolve_replace, resolve_reverse, resolve_join, unwrap_parens, fold_concat]


# ---------------------------------------------------------------- embedded payloads
_B64_CALL = re.compile(r"FromBase64String\s*\(\s*(" + _LIT + r")\s*\)", re.I)
_B64_BARE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{60,}={0,2})(?![A-Za-z0-9+/=])")
_NESTED_HOST = re.compile(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n;|]*")


def _extract_payloads(text: str, r: DeobResult) -> list[Layer]:
    found: list[Layer] = []
    seen: set[str] = set()
    for m in _B64_CALL.finditer(text):
        blob = _unquote(m.group(1))
        data = _try_b64(re.sub(r"\s", "", blob))
        if data is None:
            continue
        t = _bytes_to_text(data)
        if t and t not in seen:
            seen.add(t)
            src = "FromBase64String"
            if re.search(r"(?i)GzipStream|DeflateStream|IO\.Compression", text):
                src += "+decompress"
                r.hit("compressed-payload")
            r.hit("base64-payload")
            found.append(Layer(src, t))
    for m in _NESTED_HOST.finditer(text):
        pc = cmdline.parse(m.group(0))
        if pc.encoded and pc.script and pc.script not in seen:
            seen.add(pc.script)
            r.hit("nested-encoded-command")
            found.append(Layer("nested -EncodedCommand", pc.script))
    for m in _B64_BARE.finditer(text):
        data = _try_b64(m.group(1))
        t = _bytes_to_text(data) if data else None
        if t and t not in seen and len(t.strip()) > 8:
            seen.add(t)
            r.hit("base64-blob")
            found.append(Layer("base64 blob", t))
    return found


def normalize(text: str, r: DeobResult) -> str:
    for _ in range(MAX_ROUNDS):
        before = text
        for t in TRANSFORMS:
            text = t(text, r)
        if text == before:
            break
    return text


def deobfuscate(script: str, r: DeobResult | None = None, depth: int = 0,
                source: str = "input") -> DeobResult:
    r = r or DeobResult()
    norm = normalize(script, r)
    r.layers.append(Layer(source, norm))
    if depth >= MAX_DEPTH:
        r.hit("max-depth-reached")
        return r
    for layer in _extract_payloads(norm, r):
        deobfuscate(layer.text, r, depth + 1, layer.source)
    return r
