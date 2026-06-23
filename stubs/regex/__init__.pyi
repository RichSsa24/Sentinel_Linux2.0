"""Minimal local type stub for the subset of the `regex` module we use.

`regex` is used instead of stdlib `re` for one reason: its ``timeout`` argument
makes regular-expression matching ReDoS-safe against hostile rule-supplied
patterns (stdlib `re` cannot be interrupted). It ships no inline types, so this
stub pins just ``compile``, the two match methods we call (both with the
``timeout`` keyword), the ``error`` exception, and the ``IGNORECASE`` flag.
A match that exceeds ``timeout`` raises the builtin ``TimeoutError``.
"""

class error(Exception): ...

class Match:
    def group(self, group: int = ..., /) -> str: ...
    def start(self, group: int = ..., /) -> int: ...

class Pattern:
    def search(self, string: str, *, timeout: float | None = ...) -> Match | None: ...
    def fullmatch(self, string: str, *, timeout: float | None = ...) -> Match | None: ...

def compile(pattern: str, flags: int = ...) -> Pattern: ...

IGNORECASE: int
I: int
