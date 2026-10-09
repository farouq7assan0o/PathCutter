"""Shared plumbing for the infrastructure-as-code extractors."""
from __future__ import annotations

import re

from ..changes import ChangeSpec, ChangeWarning


class Sink:
    """Collects the changes and warnings of one file, de-duplicated, with origins `file:line`."""

    def __init__(self, origin: str, start_index: int = 1):
        self.origin = origin
        self.index = start_index
        self.specs: list[ChangeSpec] = []
        self.warns: list[ChangeWarning] = []
        self._seen: set[tuple] = set()

    def add(self, op: str, source: str, edge: str, target: str, line: int, raw: str = "", *, new_type: str = "",
            deny: bool = False, ttl: int | None = None) -> None:
        key = (op, source.lower(), edge, target.lower(), new_type, deny)
        if key in self._seen:
            return
        self._seen.add(key)
        self.specs.append(ChangeSpec(self.index, op, source=source, edge_type=edge, target=target, new_type=new_type,
                                     origin=f"{self.origin}:{line}", raw=raw or f"{op} {source} {edge} {target}",
                                     deny=deny, ttl_minutes=ttl))
        self.index += 1

    def create(self, kind: str, name: str, line: int, raw: str = "") -> None:
        self.add("create", name, "if-missing", "", line, raw, new_type=kind)

    def warn(self, line: int, message: str, raw: str = "", level: str = "review") -> None:
        self.warns.append(ChangeWarning(f"{self.origin}:{line}", message, raw, level))

    def result(self):
        return self.specs, self.warns


_GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")


def is_guid(v) -> bool:
    return isinstance(v, str) and bool(_GUID.match(v))


def short_name(v: str) -> str:
    """CN=Domain Admins,OU=x,DC=a,DC=b -> Domain Admins ; CORP\\alice -> alice ; alice@corp.local stays as is."""
    from ..changes import _normalise_ref
    return _normalise_ref(v)
