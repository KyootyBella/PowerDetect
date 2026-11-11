"""Parse a raw process command line (as seen in Defender's ProcessCommandLine)
into the PowerShell host flags and the script payload. Never executes anything."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

# powershell.exe accepts any unambiguous prefix of a parameter name, with - or /
_PARAMS = {
    "encodedcommand": ["e", "ec", "en", "enc", "enco", "encod", "encode", "encoded",
                       "encodedc", "encodedco", "encodedcom", "encodedcomm",
                       "encodedcomma", "encodedcomman", "encodedcommand"],
    "command": ["c", "co", "com", "comm", "comma", "comman", "command"],
    "file": ["f", "fi", "fil", "file"],
    "windowstyle": ["w", "wi", "win", "wind", "windo", "window", "windows",
                    "windowst", "windowsty", "windowstyl", "windowstyle"],
    "executionpolicy": ["ep", "ex", "exe", "exec", "execu", "execut", "executi",
                        "executio", "execution", "executionp", "executionpo",
                        "executionpol", "executionpoli", "executionpolic",
                        "executionpolicy"],
    "noprofile": ["nop", "nopr", "nopro", "noprof", "noprofi", "noprofil", "noprofile"],
    "noninteractive": ["noni", "nonin", "nonint", "noninte", "noninter",
                       "noninteractive", "noninteract", "noninteracti", "noninteractiv"],
    "nologo": ["nol", "nolo", "nolog", "nologo"],
    "sta": ["sta"], "mta": ["mta"],
    "version": ["v", "ve", "ver", "vers", "versi", "versio", "version"],
}
_ALIAS = {a: full for full, al in _PARAMS.items() for a in al}
_TAKES_VALUE = {"encodedcommand", "file", "windowstyle", "executionpolicy", "version"}

# The host must be the FIRST token of the command line (Defender's ProcessCommandLine
# always starts with the executable), optionally behind "cmd /c [start ...]".
# A "powershell.exe" appearing later (e.g. inside sc.exe binPath=) is just script text.
_CMD_PREFIX = re.compile(
    r"(?i)^\s*\"?(?:[^\s\"]*[\\/])?cmd(?:\.exe)?\"?\s+(?:/[a-z]\s+)*?/[ckr]\s*"
    r"(?:\"?\s*start\s+(?:/\w+\s+|\"[^\"]*\"\s+)*)?")
_HOST_RE = re.compile(
    r"(?i)^\s*[\"']?(?:[^\s\"']*[\\/])?(powershell(?:_ise)?|pwsh)(?:\.exe)?[\"']?(?=[\s\"']|$)")


@dataclass
class ParsedCommand:
    raw: str
    host: str | None = None
    flags: dict[str, str | bool] = field(default_factory=dict)
    script: str = ""
    encoded: bool = False
    decode_error: str | None = None
    cmd_wrapper: bool = False


def _tokenize(s: str) -> list[str]:
    """Windows-ish argv split: whitespace separated, double quotes group."""
    tokens, cur, inq, i = [], [], False, 0
    while i < len(s):
        ch = s[i]
        if ch == '"':
            inq = not inq
        elif ch.isspace() and not inq:
            if cur:
                tokens.append("".join(cur)); cur = []
        else:
            cur.append(ch)
        i += 1
    if cur:
        tokens.append("".join(cur))
    return tokens


def decode_b64_utf16(blob: str) -> str:
    blob = re.sub(r"[^A-Za-z0-9+/=]", "", blob)
    blob += "=" * (-len(blob) % 4)
    data = base64.b64decode(blob)
    # -EncodedCommand is UTF-16LE; fall back to utf-8 if it clearly isn't
    if len(data) > 1 and data[1::2].count(0) > len(data) // 4:
        return data.decode("utf-16-le", errors="replace")
    return data.decode("utf-8", errors="replace")


def parse(raw: str) -> ParsedCommand:
    pc = ParsedCommand(raw=raw)
    text = raw.strip()
    cm = _CMD_PREFIX.match(text)
    if cm:
        rest = text[cm.end():].replace("^", "")  # cmd caret escapes
        if _HOST_RE.match(rest):
            pc.cmd_wrapper = True
            text = rest
    m = _HOST_RE.match(text)
    if not m:
        # Not a host invocation: treat the whole thing as script (e.g. AMSI content,
        # or another program's command line that merely mentions powershell)
        pc.script = raw
        return pc
    pc.host = m.group(1).lower()
    tokens = _tokenize(text[m.end():])
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok[:1] in ("-", "/", "–", "—") and len(tok) > 1:
            name = tok.lstrip("-/–—").lower().rstrip(":")
            full = _ALIAS.get(name)
            if full == "command":
                pc.script = " ".join(tokens[i + 1:])
                break
            if full in _TAKES_VALUE:
                val = tokens[i + 1] if i + 1 < len(tokens) else ""
                pc.flags[full] = val
                if full == "encodedcommand":
                    pc.encoded = True
                    try:
                        pc.script = decode_b64_utf16(val)
                    except Exception as e:  # noqa: BLE001
                        pc.decode_error = str(e)
                i += 2
                continue
            if full:
                pc.flags[full] = True
                i += 1
                continue
            if name == "":  # "-" means read from stdin
                i += 1
                continue
            # unknown flag: keep going
            pc.flags[f"unknown:{name}"] = True
            i += 1
            continue
        # first positional = command text
        if not pc.script:
            pc.script = " ".join(tokens[i:])
        break
    return pc
