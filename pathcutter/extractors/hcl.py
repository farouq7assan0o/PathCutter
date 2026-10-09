"""A small HCL2 reader: enough to read Terraform resource blocks without running Terraform.

Understands blocks, attributes, strings (with escapes and `${}` templates), numbers, booleans, null, lists, objects,
references (`ad_group.admins.object_id`, `var.x`), function calls, heredocs and all three comment styles. Anything it
cannot evaluate becomes an `Unresolved` value that remembers its source text, so callers can report it instead of guessing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


class HclError(ValueError):
    pass


@dataclass(frozen=True)
class Ref:
    """A reference such as ad_group.admins.object_id or var.users."""
    path: str


@dataclass(frozen=True)
class Unresolved:
    text: str


@dataclass
class Block:
    kind: str
    labels: list[str]
    attrs: dict = field(default_factory=dict)
    blocks: list["Block"] = field(default_factory=list)
    line: int = 0


_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_NUM = re.compile(r"-?\d+(\.\d+)?([eE][+-]?\d+)?")


class _Parser:
    def __init__(self, text: str):
        self.s = text
        self.i = 0
        self.n = len(text)

    # ---- low level
    def line(self) -> int:
        return self.s.count("\n", 0, self.i) + 1

    def skip(self, newlines: bool = True) -> None:
        while self.i < self.n:
            c = self.s[self.i]
            if c in " \t\r" or (newlines and c == "\n"):
                self.i += 1
            elif c == "#" or self.s.startswith("//", self.i):
                while self.i < self.n and self.s[self.i] != "\n":
                    self.i += 1
            elif self.s.startswith("/*", self.i):
                end = self.s.find("*/", self.i + 2)
                self.i = self.n if end < 0 else end + 2
            else:
                break

    def peek(self) -> str:
        return self.s[self.i] if self.i < self.n else ""

    def expect(self, ch: str) -> None:
        self.skip()
        if self.peek() != ch:
            raise HclError(f"line {self.line()}: expected '{ch}'")
        self.i += 1

    # ---- structure
    def body(self, until: str = "") -> tuple[dict, list[Block]]:
        attrs: dict = {}
        blocks: list[Block] = []
        while True:
            self.skip()
            if self.i >= self.n:
                if until:
                    raise HclError(f"line {self.line()}: unclosed '{{'")
                return attrs, blocks
            if until and self.peek() == until:
                self.i += 1
                return attrs, blocks
            m = _IDENT.match(self.s, self.i)
            if not m:
                raise HclError(f"line {self.line()}: unexpected '{self.peek()}'")
            name, start_line = m.group(0), self.line()
            self.i = m.end()
            self.skip(newlines=False)
            if self.peek() == "=" and not self.s.startswith("==", self.i):
                self.i += 1
                attrs[name] = self.expr()
                continue
            labels: list[str] = []
            while True:
                self.skip(newlines=False)
                if self.peek() == '"':
                    labels.append(self.string_plain())
                elif _IDENT.match(self.s, self.i):
                    mm = _IDENT.match(self.s, self.i)
                    labels.append(mm.group(0))
                    self.i = mm.end()
                else:
                    break
            self.skip(newlines=False)
            if self.peek() != "{":
                raise HclError(f"line {self.line()}: expected '=' or a block after '{name}'")
            self.i += 1
            a, b = self.body("}")
            blocks.append(Block(name, labels, a, b, start_line))

    # ---- values
    def string_plain(self) -> str:
        v = self.string()
        return v if isinstance(v, str) else v.text

    def string(self):
        """A double-quoted string; returns a str, or Unresolved when it contains a ${...} template."""
        assert self.peek() == '"'
        self.i += 1
        out, templ = [], False
        start = self.i - 1
        while self.i < self.n:
            c = self.s[self.i]
            if c == "\\":
                nxt = self.s[self.i + 1:self.i + 2]
                out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(nxt, nxt))
                self.i += 2
            elif c == '"':
                self.i += 1
                text = "".join(out)
                return Unresolved(self.s[start:self.i]) if templ else text
            elif self.s.startswith("${", self.i) or self.s.startswith("%{", self.i):
                depth, j = 1, self.i + 2
                while j < self.n and depth:
                    depth += {"{": 1, "}": -1}.get(self.s[j], 0)
                    j += 1
                out.append(self.s[self.i:j])
                self.i = j
                templ = True
            else:
                out.append(c)
                self.i += 1
        raise HclError(f"line {self.line()}: unterminated string")

    def heredoc(self):
        m = re.compile(r"<<-?([A-Za-z_][A-Za-z0-9_]*)\n").match(self.s, self.i)
        if not m:
            raise HclError(f"line {self.line()}: bad heredoc")
        tag, start = m.group(1), m.end()
        end = re.compile(r"^[ \t]*" + re.escape(tag) + r"[ \t]*$", re.M).search(self.s, start)
        if not end:
            raise HclError(f"line {self.line()}: unterminated heredoc")
        body = self.s[start:end.start()]
        self.i = end.end()
        return Unresolved(body) if "${" in body else body

    def expr(self):
        self.skip()
        c = self.peek()
        if c == '"':
            v = self.string()
        elif self.s.startswith("<<", self.i):
            v = self.heredoc()
        elif c == "[":
            v = self.list()
        elif c == "{":
            v = self.obj()
        elif c == "(":
            v = Unresolved(self.balanced("(", ")"))
        else:
            v = self.atom()
        return self.tail(v)

    def tail(self, v):
        """Conditionals, arithmetic, splats and index/attr access after a value make it unevaluable."""
        start = self.i
        self.skip(newlines=False)
        c = self.peek()
        if c in ("?", "+", "-", "*", "/", "%", "&", "|", "<", ">", "!") or (c == "=" and self.s.startswith("==", self.i)):
            end = self.i
            while end < self.n and self.s[end] != "\n":
                end += 1
            text = self.s[start:end]
            self.i = end
            return Unresolved(f"{v!r}{text}")
        if c == "." and self.s.startswith(".*", self.i):
            self.i += 2
            return Unresolved("splat")
        self.i = start
        return v

    def balanced(self, open_: str, close: str) -> str:
        start, depth = self.i, 0
        while self.i < self.n:
            c = self.s[self.i]
            if c == '"':
                self.string()
                continue
            depth += {open_: 1, close: -1}.get(c, 0)
            self.i += 1
            if depth == 0:
                return self.s[start:self.i]
        raise HclError(f"line {self.line()}: unbalanced '{open_}'")

    def list(self):
        self.i += 1
        items = []
        while True:
            self.skip()
            if self.peek() == "]":
                self.i += 1
                return items
            if re.match(r"for\b", self.s[self.i:self.i + 4]):
                self.i -= 1
                return Unresolved(self.balanced("[", "]"))
            items.append(self.expr())
            self.skip()
            if self.peek() == ",":
                self.i += 1
            elif self.peek() != "]":
                raise HclError(f"line {self.line()}: expected ',' or ']'")

    def obj(self):
        start = self.i
        self.i += 1
        out = {}
        while True:
            self.skip()
            if self.peek() == "}":
                self.i += 1
                return out
            if re.match(r"for\b", self.s[self.i:self.i + 4]):
                self.i = start
                return Unresolved(self.balanced("{", "}"))
            if self.peek() == '"':
                key = self.string_plain()
            else:
                m = _IDENT.match(self.s, self.i)
                if not m:
                    raise HclError(f"line {self.line()}: bad object key")
                key = m.group(0)
                self.i = m.end()
            self.skip()
            if self.peek() not in ("=", ":"):
                raise HclError(f"line {self.line()}: expected '=' in object")
            self.i += 1
            out[key] = self.expr()
            self.skip()
            if self.peek() == ",":
                self.i += 1

    def atom(self):
        m = _NUM.match(self.s, self.i)
        if m and (self.i == 0 or not self.s[self.i - 1].isalnum()):
            self.i = m.end()
            return float(m.group(0)) if "." in m.group(0) or "e" in m.group(0).lower() else int(m.group(0))
        m = _IDENT.match(self.s, self.i)
        if not m:
            raise HclError(f"line {self.line()}: unexpected '{self.peek()}'")
        word = m.group(0)
        self.i = m.end()
        if word in ("true", "false"):
            return word == "true"
        if word == "null":
            return None
        if self.peek() == "(":
            args = self.balanced("(", ")")
            return Unresolved(f"{word}{args}")
        # reference chain: a.b[0].c["x"]
        path = [word]
        while True:
            if self.peek() == "." and _IDENT.match(self.s, self.i + 1):
                mm = _IDENT.match(self.s, self.i + 1)
                path.append(mm.group(0))
                self.i = mm.end()
            elif self.peek() == "[":
                path.append(self.balanced("[", "]"))
            else:
                break
        return Ref(".".join(path))


def parse(text: str) -> list[Block]:
    """Top-level blocks of an HCL document (top-level attributes are ignored)."""
    p = _Parser(text)
    _, blocks = p.body()
    return blocks
