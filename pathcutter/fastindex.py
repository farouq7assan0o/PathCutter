"""Integer-indexed reverse adjacency for the hot loops (exposure, incremental updates).

networkx is the source of truth and stays the right tool for everything that is not a tight loop. This index is a
cache next to it: node ids become dense ints and every node keeps the list of (predecessor, edge type) that point at
it, which is exactly what the reverse search needs. It is kept in sync by AttackGraph.add_edge / remove_edge /
add_node (O(1) / O(in-degree)); bulk loads simply drop it and it is rebuilt on first use.
"""
from __future__ import annotations


class FastIndex:
    __slots__ = ("ids", "pos", "rev", "version")

    def __init__(self):
        self.ids: list[str] = []
        self.pos: dict[str, int] = {}
        self.rev: list[list[tuple[int, str]]] = []
        self.version = 0

    @classmethod
    def build(cls, nx_graph) -> "FastIndex":
        fx = cls()
        ids = list(nx_graph.nodes)
        fx.ids = ids
        fx.pos = {n: i for i, n in enumerate(ids)}
        pos = fx.pos
        rev: list[list[tuple[int, str]]] = [[] for _ in ids]
        for u, v, d in nx_graph.edges(data="edge_type"):
            rev[pos[v]].append((pos[u], d or ""))
        fx.rev = rev
        return fx

    def remove_one(self, u: str, v: str, edge_type: str) -> None:
        """Remove a single (u, edge_type) entry from v's predecessors (undo of one add_edge)."""
        iu, iv = self.pos.get(u), self.pos.get(v)
        if iu is None or iv is None:
            return
        lst = self.rev[iv]
        for k in range(len(lst) - 1, -1, -1):
            if lst[k] == (iu, edge_type):
                del lst[k]
                break
        self.version += 1

    def truncate(self, size: int) -> None:
        """Drop nodes appended after the index had `size` nodes (their edges are rolled back first)."""
        while len(self.ids) > size:
            self.pos.pop(self.ids.pop(), None)
            self.rev.pop()

    def copy(self) -> "FastIndex":
        c = FastIndex()
        c.ids, c.pos, c.rev, c.version = list(self.ids), dict(self.pos), [list(r) for r in self.rev], self.version
        return c

    def node(self, node_id: str) -> int:
        i = self.pos.get(node_id)
        if i is None:
            i = len(self.ids)
            self.pos[node_id] = i
            self.ids.append(node_id)
            self.rev.append([])
        return i

    def add_edge(self, u: str, v: str, edge_type: str) -> None:
        iu, iv = self.node(u), self.node(v)
        self.rev[iv].append((iu, edge_type))
        self.version += 1

    def remove_edge(self, u: str, v: str, edge_type: str) -> None:
        iu, iv = self.pos.get(u), self.pos.get(v)
        if iu is None or iv is None:
            return
        self.rev[iv] = [(a, t) for a, t in self.rev[iv] if not (a == iu and t == edge_type)]
        self.version += 1
