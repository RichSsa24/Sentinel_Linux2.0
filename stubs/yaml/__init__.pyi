"""Minimal local type stub for the subset of PyYAML this project uses.

PyYAML ships no inline types and we avoid the extra `types-PyYAML` dev
dependency, so this pins exactly the API the rule loader touches: ``safe_load``
and the ``YAMLError`` base exception. Kept deliberately tiny.
"""

from typing import IO, Any

class YAMLError(Exception): ...

def safe_load(stream: str | bytes | IO[str] | IO[bytes]) -> Any: ...
