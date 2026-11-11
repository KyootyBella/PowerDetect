"""Split deobfuscated PowerShell into individual statements (with offsets) so
every rule match can be attributed to the exact statement that caused it."""
from __future__ import annotations

BOUNDARIES = ";\n\r{}"


def split_statements(text: str) -> list[tuple[int, int]]:
    """Return (start, end) spans of statements. Splits on ; newlines and
    braces, but never inside quotes or parentheses. Pure scanner, no eval."""
    spans: list[tuple[int, int]] = []
    start, i, depth, quote, n = 0, 0, 0, None, len(text)

    def push(a: int, b: int) -> None:
        while a < b and text[a].isspace():
            a += 1
        while b > a and text[b - 1].isspace():
            b -= 1
        if b > a:
            spans.append((a, b))

    while i < n:
        c = text[i]
        if quote:
            if c == "`" and quote == '"':
                i += 2
                continue
            if c == quote:
                if i + 1 < n and text[i + 1] == quote:  # '' or "" escape
                    i += 2
                    continue
                quote = None
            i += 1
            continue
        if c in "'\"":
            quote = c
        elif c == "`":
            i += 2
            continue
        elif c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif c in BOUNDARIES and depth == 0:
            push(start, i)
            start = i + 1
        i += 1
    push(start, n)
    return spans
