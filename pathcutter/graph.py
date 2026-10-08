"""Attack graph construction - builds a directed multigraph from AD nodes and edges."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

import networkx as nx

from .edges import EdgeType, get_edge_type, exploitability_weight, is_tier0, EDGE_REGISTRY


class NodeType(Enum):
    USER = "User"
    COMPUTER = "Computer"
    GROUP = "Group"
    DOMAIN = "Domain"
    GPO = "GPO"
    OU = "OU"
    CONTAINER = "Container"
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


class AttackGraph:
    """Directed multigraph of AD attack relationships."""

    def __init__(self):
        self.graph: nx.DiGraph = nx.DiGraph()
        self._nodes: dict[str, ADNode] = {}
        self._tier0: set[str] = set()
        self._group_members: dict[str, set[str]] = {}  # group_id -> direct member IDs
        self._transitive_cache: dict[str, set[str]] = {}  # node_id -> all groups (transitive)

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

    def add_edge(self, edge: ADEdge) -> None:
        """Add an attack relationship to the graph."""
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

    def get_node(self, node_id: str) -> ADNode | None:
        return self._nodes.get(node_id)

    def get_node_name(self, node_id: str) -> str:
        node = self._nodes.get(node_id)
        return node.name if node else node_id

    def get_edge_data(self, source_id: str, target_id: str) -> dict | None:
        return self.graph.get_edge_data(source_id, target_id)

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
        return [(u, v, d) for u, v, d in self.graph.edges(node_id, data=True)]

    def in_edges(self, node_id: str) -> list[tuple[str, str, dict]]:
        """All incoming edges to a node with their data."""
        if node_id not in self.graph:
            return []
        return [(u, v, d) for u, v, d in self.graph.in_edges(node_id, data=True)]

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
            for _, target, data in self.graph.edges(current, data=True):
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
            if node and node.node_type == NodeType.GROUP:
                members = self._recursive_members(t0_id)
                for member_id in members:
                    member = self._nodes.get(member_id)
                    if member:
                        member.tier = 0
                        self._tier0.add(member_id)

        # Phase 2: Mark nodes with direct admin access to Tier 0 as Tier 1
        for t0_id in self._tier0:
            for source_id in self.predecessors(t0_id):
                edge_data = self.get_edge_data(source_id, t0_id)
                if edge_data and edge_data.get("edge_type") in ("AdminTo", "CanRDP", "CanPSRemote"):
                    node = self._nodes.get(source_id)
                    if node and node.tier > 1:
                        node.tier = 1

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

    def subgraph(self, node_ids: set[str]) -> AttackGraph:
        """Create a new AttackGraph containing only the specified nodes and edges between them."""
        sub = AttackGraph()
        for nid in node_ids:
            node = self._nodes.get(nid)
            if node:
                sub.add_node(node)
        for u, v, data in self.graph.edges(data=True):
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
        for _, _, data in self.graph.edges(data=True):
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
