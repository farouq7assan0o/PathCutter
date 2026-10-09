"""Attack graph construction - builds a directed multigraph from AD nodes and edges."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum

import networkx as nx
from contextlib import contextmanager

from .edges import EdgeType, get_edge_type, exploitability_weight, is_tier0, EDGE_REGISTRY


class NodeType(Enum):
    USER = "User"
    COMPUTER = "Computer"
    GROUP = "Group"
    DOMAIN = "Domain"
    GPO = "GPO"
    OU = "OU"
    CONTAINER = "Container"
    CERT_TEMPLATE = "CertTemplate"
    ENTERPRISE_CA = "EnterpriseCA"
    ROOT_CA = "RootCA"
    AIACA = "AIACA"
    NTAUTH_STORE = "NTAuthStore"
    AZ_USER = "AZUser"
    AZ_GROUP = "AZGroup"
    AZ_APP = "AZApp"
    AZ_SP = "AZServicePrincipal"
    AZ_ROLE = "AZRole"
    AZ_TENANT = "AZTenant"
    UNKNOWN = "Unknown"


@dataclass
class ADNode:
    """A single Active Directory object."""
    object_id: str  # SID or GUID
    name: str
    node_type: NodeType
    domain: str = ""
    enabled: bool = True
    admin_count: bool = False
    tier: int = 2  # 0=Tier 0, 1=Tier 1, 2=Tier 2
    properties: dict = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        if "@" in self.name:
            return self.name.split("@")[0]
        return self.name


@dataclass(frozen=True)
class Deny:
    """A Deny ACE: `principal` (and, if it is a group, everyone in it) may NOT use `edge_type` on `target_id`.

    A deny wins over every allow, but only for identities in the denied principal's token, so it cannot be
    modeled by deleting the edge: other identities keep the right. See exposure.py.
    """
    principal_id: str
    edge_type: str
    target_id: str


@dataclass
class ADEdge:
    """A single attack relationship between two AD objects."""
    source_id: str
    target_id: str
    edge_type: str  # matches EdgeType.name
    inherited: bool = False
    properties: dict = field(default_factory=dict)

    @property
    def type_info(self) -> EdgeType | None:
        return get_edge_type(self.edge_type)


def _copy_nx(G):
    """Structural copy of a MultiDiGraph (about 1.5x faster than G.copy(): no per-edge Python call chain)."""
    new = nx.MultiDiGraph()
    new.graph.update(G.graph)
    new._node = {n: dict(a) for n, a in G._node.items()}
    succ = {n: {} for n in G._node}
    pred = {n: {} for n in G._node}
    for u, nbrs in G._succ.items():
        su = succ[u]
        for v, keys in nbrs.items():
            nk = {k: dict(a) for k, a in keys.items()}
            su[v] = nk
            pred[v][u] = nk
    new._succ = succ
    new._adj = succ
    new._pred = pred
    return new


class AttackGraph:
    """Directed multigraph of AD attack relationships."""

    def __init__(self):
        self.graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._nodes: dict[str, ADNode] = {}
        self._tier0: set[str] = set()
        self._group_members: dict[str, set[str]] = {}  # group_id -> direct member IDs
        self._transitive_cache: dict[str, set[str]] = {}  # node_id -> all groups (transitive)
        self.denies: set[Deny] = set()                    # Deny ACEs (identity-sensitive, see Deny)
        self._fx = None                                   # FastIndex cache, see fastindex.py
        self._shared = False                              # self.graph is shared with a clone: copy before writing
        self._journal: list | None = None                 # set inside probe(): every write is undoable
        self._seed_t0: set[str] = set()                   # Tier 0 by name/SID alone (what retier starts from)
        self._tiered: set[str] = set()                    # ids whose tier is below 2 (what retier must reset)

    def _own(self) -> None:
        """Copy-on-write: clone() shares the networkx graph; the first writer on either side takes its own copy."""
        if self._shared and self._journal is None:
            self.graph = _copy_nx(self.graph)
            self._shared = False

    @contextmanager
    def probe(self, extra_tier0=None):
        """Try changes in place, even on storage shared with a clone, and undo ALL of them on exit.

        Trial changes then cost O(change) instead of a full graph copy. Every node/edge write is journaled and replayed
        backwards on exit (also on an exception), tiers are recomputed, and the integer index is truncated back.
        Bulk loads are not allowed inside a probe.
        """
        if self._journal is not None:
            raise RuntimeError("probe() cannot be nested")
        fx_size = len(self._fx.ids) if self._fx is not None else None
        denies = set(self.denies)
        self._journal = journal = []
        try:
            yield self
        finally:
            self._journal = None
            self._rollback(journal)
            self.denies = denies
            if self._fx is not None and fx_size is not None:
                self._fx.truncate(fx_size)
            self._transitive_cache.clear()
            self.retier(extra_tier0)

    def _rollback(self, journal: list) -> None:
        g = self.graph
        for entry in reversed(journal):
            kind = entry[0]
            if kind == "e+":
                _, u, v, key, et = entry
                if g.has_edge(u, v, key):
                    g.remove_edge(u, v, key)
                    if self._fx is not None:
                        self._fx.remove_one(u, v, et)
                    if et == "MemberOf" and not self.has_edge_type(u, v, "MemberOf"):
                        self._group_members.get(v, set()).discard(u)
            elif kind == "e-":
                _, u, v, removed, et = entry
                for key, attrs in removed:
                    if not g.has_edge(u, v, key):
                        g.add_edge(u, v, key, **attrs)
                        if self._fx is not None:
                            self._fx.add_edge(u, v, et)
                if et == "MemberOf" and removed:
                    self._group_members.setdefault(v, set()).add(u)
            elif kind == "n":
                _, nid, prev, attrs = entry
                if prev is None:
                    if nid in g:
                        g.remove_node(nid)
                    self._nodes.pop(nid, None)
                    self._seed_t0.discard(nid)
                    self._tier0.discard(nid)
                    self._tiered.discard(nid)
                else:
                    self._nodes[nid] = prev
                    if attrs is not None:
                        g.add_node(nid, **attrs)

    def fast(self):
        """Integer-indexed reverse adjacency (built on first use, kept in sync by add_edge/remove_edge)."""
        if self._fx is None:
            from .fastindex import FastIndex
            self._fx = FastIndex.build(self.graph)
        return self._fx

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return self.graph.number_of_edges()

    @property
    def tier0_nodes(self) -> set[str]:
        return self._tier0

    def add_node(self, node: ADNode) -> None:
        """Add an AD node to the graph."""
        self._own()
        if self._journal is not None:
            nid = node.object_id
            self._journal.append(("n", nid, self._nodes.get(nid), dict(self.graph.nodes[nid]) if nid in self.graph else None))
        self._nodes[node.object_id] = node
        self.graph.add_node(
            node.object_id,
            name=node.name,
            type=node.node_type.value,
            domain=node.domain,
            enabled=node.enabled,
            tier=node.tier,
        )
        if self._fx is not None:
            self._fx.node(node.object_id)
        if is_tier0(node.name, node.object_id, node.node_type.value):
            node.tier = 0
            self._tier0.add(node.object_id)
            self._seed_t0.add(node.object_id)
        else:
            self._seed_t0.discard(node.object_id)      # the node was replaced by one that is no longer Tier 0 by name
        if node.tier < 2:
            self._tiered.add(node.object_id)

    def add_edge(self, edge: ADEdge) -> None:
        """Add an attack relationship to the graph."""
        self._own()
        if self._fx is not None:
            self._fx.add_edge(edge.source_id, edge.target_id, edge.edge_type)
        weight = exploitability_weight(edge.edge_type)
        key = self.graph.add_edge(
            edge.source_id,
            edge.target_id,
            edge_type=edge.edge_type,
            inherited=edge.inherited,
            weight=weight,
            **edge.properties,
        )
        if self._journal is not None:
            self._journal.append(("e+", edge.source_id, edge.target_id, key, edge.edge_type))
        if edge.edge_type == "MemberOf":
            self._group_members.setdefault(edge.target_id, set()).add(edge.source_id)
            if self._transitive_cache:
                self._transitive_cache.clear()

    def add_edges_bulk(self, edges: list[ADEdge]) -> None:
        """Add multiple edges efficiently (defers cache invalidation)."""
        if self._journal is not None:
            raise RuntimeError("bulk loads are not allowed inside probe()")
        self._own()
        self._fx = None
        for edge in edges:
            weight = exploitability_weight(edge.edge_type)
            self.graph.add_edge(
                edge.source_id,
                edge.target_id,
                edge_type=edge.edge_type,
                inherited=edge.inherited,
                weight=weight,
                **edge.properties,
            )
            if edge.edge_type == "MemberOf":
                self._group_members.setdefault(edge.target_id, set()).add(edge.source_id)
        self._transitive_cache.clear()

    def add_nodes_bulk(self, nodes: list[ADNode]) -> None:
        if self._journal is not None:
            raise RuntimeError("bulk loads are not allowed inside probe()")
        self._own()
        self._fx = None
        """Add multiple nodes efficiently."""
        for node in nodes:
            self._nodes[node.object_id] = node
            self.graph.add_node(
                node.object_id,
                name=node.name,
                type=node.node_type.value,
                domain=node.domain,
                enabled=node.enabled,
                tier=node.tier,
            )
            if is_tier0(node.name, node.object_id, node.node_type.value):
                node.tier = 0
                self._tier0.add(node.object_id)
                self._seed_t0.add(node.object_id)
            if node.tier < 2:
                self._tiered.add(node.object_id)

    def clone(self) -> "AttackGraph":
        """Independent deep copy (own nodes, edges, tier state), built by copying structures rather than re-adding."""
        new = AttackGraph()
        new.graph = self.graph                           # shared until either side writes (see _own)
        new._shared = self._shared = True
        new._nodes = {k: ADNode(n.object_id, n.name, n.node_type, n.domain, n.enabled, n.admin_count, n.tier,
                                dict(n.properties)) for k, n in self._nodes.items()}
        new._tier0 = set(self._tier0)
        new._seed_t0 = set(self._seed_t0)
        new._tiered = set(self._tiered)
        new._group_members = {k: set(v) for k, v in self._group_members.items()}
        new.denies = set(self.denies)
        if self._fx is not None:
            new._fx = self._fx.copy()
        return new

    def deny_actor_sets(self) -> list[tuple[Deny, frozenset[str]]]:
        """Each deny with the identities it binds: the principal plus, for a group, all its (nested) members.
        Denies that bind nothing present in the graph, or that guard an edge that does not exist, are dropped."""
        out = []
        for d in sorted(self.denies, key=lambda x: (x.principal_id, x.edge_type, x.target_id)):
            if d.principal_id not in self._nodes or d.target_id not in self._nodes:
                continue
            if not self.has_incoming_type(d.target_id, d.edge_type):
                continue
            actors = {d.principal_id}
            if d.principal_id in self._group_members or self._nodes[d.principal_id].node_type == NodeType.GROUP:
                actors |= self._recursive_members(d.principal_id)
            out.append((d, frozenset(actors)))
        return out

    def has_incoming_type(self, target_id: str, edge_type: str) -> bool:
        return any(d.get("edge_type") == edge_type for _, _, d in self.graph.in_edges(target_id, data=True))

    def has_edge_type(self, source_id: str, target_id: str, edge_type: str) -> bool:
        return any(d.get("edge_type") == edge_type for d in self.get_edge_data(source_id, target_id))

    def remove_edge(self, source_id: str, target_id: str, edge_type: str) -> int:
        """Remove every edge of this type between the two nodes. Returns how many were removed."""
        data = self.graph.get_edge_data(source_id, target_id)
        if not data:
            return 0
        keys = [k for k, d in data.items() if d.get("edge_type") == edge_type]
        if keys:
            self._own()
        if keys and self._journal is not None:
            self._journal.append(("e-", source_id, target_id, [(k, dict(data[k])) for k in keys], edge_type))
        for k in keys:
            self.graph.remove_edge(source_id, target_id, k)
        if keys and self._fx is not None:
            self._fx.remove_edge(source_id, target_id, edge_type)
        if keys and edge_type == "MemberOf":
            if not self.has_edge_type(source_id, target_id, "MemberOf"):
                self._group_members.get(target_id, set()).discard(source_id)
            self._transitive_cache.clear()
        return len(keys)

    def retier(self, extra_tier0: set[str] | None = None) -> None:
        """Recompute every tier from scratch.

        Needed after the graph is edited: classify_tiers() only ever promotes,
        so a removed membership would otherwise leave a stale Tier 0 behind.
        extra_tier0 lets a caller declare additional crown-jewel object ids.
        """
        nodes, gn = self._nodes, self.graph.nodes
        for nid in self._tiered:                       # only what was raised above Tier 2 needs resetting
            node = nodes.get(nid)
            if node is not None:
                node.tier = 2
        self._tiered = set()
        self._tier0 = set()
        seeds = set(self._seed_t0)
        if extra_tier0:
            seeds |= {i for i in extra_tier0 if i in nodes}
        for nid in seeds:
            nodes[nid].tier = 0
            self._tier0.add(nid)
        self._tiered |= seeds
        self._transitive_cache.clear()
        self.classify_tiers()
        # (the networkx node attribute "tier" is never read; ADNode.tier is the source of truth)

    def get_node(self, node_id: str) -> ADNode | None:
        return self._nodes.get(node_id)

    def get_node_name(self, node_id: str) -> str:
        node = self._nodes.get(node_id)
        return node.name if node else node_id

    def get_edge_data(self, source_id: str, target_id: str) -> list[dict]:
        """Return all edges between source and target (MultiDiGraph can have multiple)."""
        data = self.graph.get_edge_data(source_id, target_id)
        if data is None:
            return []
        return list(data.values())

    def successors(self, node_id: str) -> list[str]:
        """Nodes reachable in one hop from this node."""
        if node_id not in self.graph:
            return []
        return list(self.graph.successors(node_id))

    def predecessors(self, node_id: str) -> list[str]:
        """Nodes that can reach this node in one hop."""
        if node_id not in self.graph:
            return []
        return list(self.graph.predecessors(node_id))

    def out_edges(self, node_id: str) -> list[tuple[str, str, dict]]:
        """All outgoing edges from a node with their data."""
        if node_id not in self.graph:
            return []
        return [(u, v, d) for u, v, _, d in self.graph.edges(node_id, data=True, keys=True)]

    def in_edges(self, node_id: str) -> list[tuple[str, str, dict]]:
        """All incoming edges to a node with their data."""
        if node_id not in self.graph:
            return []
        return [(u, v, d) for u, v, _, d in self.graph.in_edges(node_id, data=True, keys=True)]

    def transitive_group_memberships(self, node_id: str) -> set[str]:
        """All groups a node belongs to, transitively (follows nested MemberOf chains)."""
        if node_id in self._transitive_cache:
            return self._transitive_cache[node_id]

        visited = set()
        stack = [node_id]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            for _, target, _, data in self.graph.edges(current, data=True, keys=True):
                if data.get("edge_type") == "MemberOf" and target not in visited:
                    stack.append(target)

        visited.discard(node_id)  # don't include self
        self._transitive_cache[node_id] = visited
        return visited

    def effective_permissions(self, node_id: str) -> dict[str, list[str]]:
        """All edge types this node has to other nodes, including through group membership.
        Returns {target_id: [edge_type1, edge_type2, ...]}."""
        perms: dict[str, list[str]] = {}

        # Direct edges
        for _, target, data in self.out_edges(node_id):
            edge_type = data.get("edge_type", "")
            if edge_type != "MemberOf":
                perms.setdefault(target, []).append(edge_type)

        # Inherited through group membership
        for group_id in self.transitive_group_memberships(node_id):
            for _, target, data in self.out_edges(group_id):
                edge_type = data.get("edge_type", "")
                if edge_type != "MemberOf":
                    perms.setdefault(target, []).append(f"{edge_type} (via {self.get_node_name(group_id)})")

        return perms

    def classify_tiers(self) -> None:
        """Classify all nodes into tiers based on group membership and proximity to Tier 0."""
        # Phase 1: Mark Tier 0 (already done in add_node for known groups)
        # Also mark members of Tier 0 groups as Tier 0
        for t0_id in list(self._tier0):
            node = self._nodes.get(t0_id)
            if node and node.node_type in (NodeType.GROUP, NodeType.AZ_ROLE, NodeType.AZ_GROUP):
                members = self._recursive_members(t0_id)
                for member_id in members:
                    member = self._nodes.get(member_id)
                    if member:
                        member.tier = 0
                        self._tier0.add(member_id)
                        self._tiered.add(member_id)

        # Phase 2: Mark nodes with direct admin access to Tier 0 as Tier 1
        for t0_id in self._tier0:
            for source_id in self.predecessors(t0_id):
                edge_list = self.get_edge_data(source_id, t0_id)
                for ed in edge_list:
                    if ed.get("edge_type") in ("AdminTo", "CanRDP", "CanPSRemote"):
                        node = self._nodes.get(source_id)
                        if node and node.tier > 1:
                            node.tier = 1
                            self._tiered.add(source_id)

    def _recursive_members(self, group_id: str) -> set[str]:
        """All members of a group, recursively."""
        members = set()
        stack = list(self._group_members.get(group_id, set()))
        while stack:
            member_id = stack.pop()
            if member_id in members:
                continue
            members.add(member_id)
            # If member is also a group, add its members
            if member_id in self._group_members:
                stack.extend(self._group_members[member_id])
        return members

    def nodes_by_type(self, node_type: NodeType) -> list[ADNode]:
        return [n for n in self._nodes.values() if n.node_type == node_type]

    def all_nodes(self) -> list[ADNode]:
        return list(self._nodes.values())

    def all_edges(self) -> list[tuple[str, str, dict]]:
        """All edges in the graph as (source, target, data) tuples."""
        return [(u, v, d) for u, v, _, d in self.graph.edges(data=True, keys=True)]

    def subgraph(self, node_ids: set[str]) -> AttackGraph:
        """Create a new AttackGraph containing only the specified nodes and edges between them."""
        sub = AttackGraph()
        for nid in node_ids:
            node = self._nodes.get(nid)
            if node:
                sub.add_node(node)
        for u, v, _, data in self.graph.edges(data=True, keys=True):
            if u in node_ids and v in node_ids:
                sub.add_edge(ADEdge(
                    source_id=u,
                    target_id=v,
                    edge_type=data.get("edge_type", ""),
                    inherited=data.get("inherited", False),
                ))
        return sub

    def summary(self) -> dict:
        """Quick summary stats."""
        type_counts = {}
        for node in self._nodes.values():
            type_counts[node.node_type.value] = type_counts.get(node.node_type.value, 0) + 1

        edge_type_counts = {}
        for _, _, _, data in self.graph.edges(data=True, keys=True):
            et = data.get("edge_type", "Unknown")
            edge_type_counts[et] = edge_type_counts.get(et, 0) + 1

        tier_counts = {0: 0, 1: 0, 2: 0}
        for node in self._nodes.values():
            tier_counts[node.tier] = tier_counts.get(node.tier, 0) + 1

        return {
            "total_nodes": self.node_count,
            "total_edges": self.edge_count,
            "node_types": type_counts,
            "edge_types": edge_type_counts,
            "tier_0_count": tier_counts[0],
            "tier_1_count": tier_counts[1],
            "tier_2_count": tier_counts[2],
        }
