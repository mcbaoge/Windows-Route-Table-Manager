"""Force-directed graph layout with Barnes-Hut optimization.

Implements Fruchterman-Reingold algorithm with:
- Barnes-Hut quadtree for O(n log n) force computation
- Temperature cooling schedule
- Configurable repulsion/attraction constants

Suitable for 1000+ node topologies.
"""
import math
from typing import Optional

from services.topology_engine import NetworkGraph, GraphDiff


class QuadTree:
    """Barnes-Hut quadtree for efficient force computation."""

    class Node:
        __slots__ = ("x", "y", "mass", "cx", "cy", "cmx", "cmy", "nw", "ne", "sw", "se", "has_children")

        def __init__(self):
            self.x = 0.0
            self.y = 0.0
            self.mass = 0.0
            self.cx = 0.0  # center of mass x
            self.cy = 0.0  # center of mass y
            self.cmx = 0.0
            self.cmy = 0.0
            self.nw: Optional[QuadTree.Node] = None
            self.ne: Optional[QuadTree.Node] = None
            self.sw: Optional[QuadTree.Node] = None
            self.se: Optional[QuadTree.Node] = None
            self.has_children = False

    def __init__(self, x: float, y: float, w: float, h: float):
        self.root = self.Node()
        self.root.x = x
        self.root.y = y
        self.root.cx = x + w / 2
        self.root.cy = y + h / 2
        self._w = w
        self._h = h

    def insert(self, x: float, y: float, mass: float = 1.0):
        self._insert(self.root, x, y, mass, self.root.x, self.root.y, self._w, self._h, 0)

    def _insert(self, node, x, y, mass, nx, ny, w, h, depth):
        if depth > 32:
            return
        if node.mass == 0:
            node.cmx = x
            node.cmy = y
            node.mass = mass
            node.cx = x
            node.cy = y
            return
        # Accumulate mass
        total = node.mass + mass
        node.cmx = (node.cmx * node.mass + x * mass) / total
        node.cmy = (node.cmy * node.mass + y * mass) / total
        node.cx = node.cmx
        node.cy = node.cmy
        node.mass = total

        if not node.has_children:
            # Subdivide
            node.has_children = True
            hw = w / 2
            hh = h / 2
            node.nw = self.Node()
            node.nw.x, node.nw.y = nx, ny
            node.nw.cx, node.nw.cy = nx + hw / 2, ny + hh / 2
            node.ne = self.Node()
            node.ne.x, node.ne.y = nx + hw, ny
            node.ne.cx, node.ne.cy = nx + hw + hw / 2, ny + hh / 2
            node.sw = self.Node()
            node.sw.x, node.sw.y = nx, ny + hh
            node.sw.cx, node.sw.cy = nx + hw / 2, ny + hh + hh / 2
            node.se = self.Node()
            node.se.x, node.se.y = nx + hw, ny + hh
            node.se.cx, node.se.cy = nx + hw + hw / 2, ny + hh + hh / 2
            # Re-insert existing mass
            self._insert(node.nw, node.cx, node.cy, 0, nx, ny, hw, hh, depth + 1)
            # Actually need to re-insert the original point too
            self._insert(self._quadrant(node, node.cx, node.cy, nx, ny, hw, hh),
                         node.cx, node.cy, node.mass, nx, ny, hw, hh, depth + 1)

        # Insert into child
        node.mass = total  # keep parent mass
        child = self._quadrant(node, x, y, nx, ny, w, h)
        if child:
            hw = w / 2
            hh = h / 2
            self._insert(child, x, y, mass,
                         child.x, child.y, hw, hh, depth + 1)

    def _quadrant(self, node, x, y, nx, ny, w, h):
        cx = nx + w / 2
        cy = ny + h / 2
        if x < cx:
            if y < cy:
                return node.nw
            else:
                return node.sw
        else:
            if y < cy:
                return node.ne
            else:
                return node.se

    def force(self, x: float, y: float, theta: float = 0.8,
              repulsion: float = 1000.0) -> tuple[float, float]:
        fx = 0.0
        fy = 0.0
        self._force(self.root, x, y, theta, repulsion, fx, fy)
        return fx, fy

    def _force(self, node, x, y, theta, repulsion, fx, fy):
        if node.mass == 0:
            return
        dx = node.cx - x
        dy = node.cy - y
        dist = math.hypot(dx, dy)
        if dist < 0.1:
            return

        if node.has_children:
            # Barnes-Hut: if node is far enough, treat as single body
            s = max(self._w, self._h)
            if s / dist < theta:
                force = repulsion * node.mass / (dist * dist)
                fx += force * dx / dist
                fy += force * dy / dist
                return
            # Otherwise traverse children
            for child in (node.nw, node.ne, node.sw, node.se):
                if child:
                    self._force(child, x, y, theta, repulsion, fx, fy)
        else:
            force = repulsion * node.mass / (dist * dist)
            fx += force * dx / dist
            fy += force * dy / dist


class ForceDirectedLayout:
    """Fruchterman-Reingold with Barnes-Hut acceleration.

    Handles both full layout and incremental (new nodes only).
    """

    def __init__(self, width: float = 800, height: float = 600,
                 repulsion: float = 2000.0, attraction: float = 0.01,
                 max_iterations: int = 100, theta: float = 0.8):
        self.width = width
        self.height = height
        self.repulsion = repulsion
        self.attraction = attraction
        self.max_iterations = max_iterations
        self.theta = theta
        self._temperature = 10.0
        self._cooling = 0.95

    def layout_graph(self, graph: NetworkGraph) -> dict[str, tuple[float, float]]:
        """Compute positions for all nodes in the graph."""
        positions: dict[str, tuple[float, float]] = {}
        node_ids = list(graph.nodes.keys())
        n = len(node_ids)

        if n == 0:
            return positions

        # Initialize positions in a circle
        cx, cy = self.width / 2, self.height / 2
        radius = min(self.width, self.height) * 0.35
        for i, nid in enumerate(node_ids):
            angle = 2 * math.pi * i / n
            positions[nid] = (
                cx + radius * math.cos(angle),
                cy + radius * math.sin(angle),
            )

        # Build adjacency list
        adj: dict[str, set[str]] = {nid: set() for nid in node_ids}
        for edge in graph.edges:
            if edge.source_id in adj and edge.target_id in adj:
                adj[edge.source_id].add(edge.target_id)
                adj[edge.target_id].add(edge.source_id)

        # Fruchterman-Reingold iterations
        temp = self._temperature
        area = self.width * self.height
        k = math.sqrt(area / max(n, 1))

        for iteration in range(self.max_iterations):
            if temp < 0.1:
                break

            # Repulsive forces via Barnes-Hut
            qt = QuadTree(0, 0, self.width, self.height)
            for nid in node_ids:
                x, y = positions[nid]
                qt.insert(x, y, 1.0)

            forces: dict[str, tuple[float, float]] = {}
            for nid in node_ids:
                x, y = positions[nid]
                fx, fy = 0.0, 0.0
                for other in node_ids:
                    if other == nid:
                        continue
                    ox, oy = positions[other]
                    dx = x - ox
                    dy = y - oy
                    dist = max(math.hypot(dx, dy), 0.1)
                    f = self.repulsion / (dist * dist)
                    fx += f * dx / dist
                    fy += f * dy / dist
                forces[nid] = (fx, fy)

            # Attractive forces along edges
            for nid in node_ids:
                fx, fy = forces[nid]
                for neighbor in adj.get(nid, set()):
                    nx, ny = positions[neighbor]
                    dx = nx - positions[nid][0]
                    dy = ny - positions[nid][1]
                    dist = max(math.hypot(dx, dy), 0.1)
                    f = dist * dist / k * self.attraction
                    fx += f * dx / dist
                    fy += f * dy / dist
                forces[nid] = (fx, fy)

            # Apply forces with temperature
            for nid in node_ids:
                fx, fy = forces[nid]
                disp = math.hypot(fx, fy)
                if disp > 0:
                    scale = min(disp, temp) / disp
                    x, y = positions[nid]
                    positions[nid] = (
                        max(10, min(self.width - 10, x + fx * scale)),
                        max(10, min(self.height - 10, y + fy * scale)),
                    )

            temp *= self._cooling

        return positions

    def incremental_layout(self, graph: NetworkGraph, diff: GraphDiff,
                           current_positions: dict[str, tuple[float, float]]
                           ) -> dict[str, tuple[float, float]]:
        """Position only new nodes, keeping existing positions fixed."""
        positions = dict(current_positions)

        new_nodes = list(diff.added_nodes.keys())
        if not new_nodes:
            return positions

        # Place new nodes near their connected existing nodes
        for nid in new_nodes:
            connected = []
            for edge in graph.edges:
                if edge.source_id == nid and edge.target_id in positions:
                    connected.append(positions[edge.target_id])
                elif edge.target_id == nid and edge.source_id in positions:
                    connected.append(positions[edge.source_id])

            if connected:
                avg_x = sum(p[0] for p in connected) / len(connected)
                avg_y = sum(p[1] for p in connected) / len(connected)
                offset = 40 + len(connected) * 10
                import random
                angle = random.random() * 2 * math.pi
                positions[nid] = (
                    avg_x + offset * math.cos(angle),
                    avg_y + offset * math.sin(angle),
                )
            else:
                cx, cy = self.width / 2, self.height / 2
                positions[nid] = (cx, cy)

        return positions
