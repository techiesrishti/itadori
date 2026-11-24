"""
Network Resilience Analyzer for Itadori mesh.

Evaluates the topological fragility of the mesh using graph-theoretic algorithms
(Tarjan's articulation points and bridge detection). Identifies Single Points
of Failure (SPOFs) where loss of a single relay would sever disconnected clusters
from the gateway, fulfilling the project's knotweed thesis ("no single root to kill").
"""
from collections import defaultdict
from typing import Dict, List, Set, Tuple

def analyze_topology(alive_nodes: Set[int], links: List[Tuple[int, int]], gw: int = 0) -> dict:
    """
    Analyzes the connectivity and failure modes of the current mesh.
    - alive_nodes: set of node IDs currently online and not crashed
    - links: list of active bi-directional (u, v) link pairs
    - gw: gateway node ID
    """
    adj = defaultdict(set)
    for u, v in links:
        if u in alive_nodes and v in alive_nodes:
            adj[u].add(v)
            adj[v].add(u)

    # 1. Connected components
    visited = set()
    components = []
    for node in sorted(alive_nodes):
        if node not in visited:
            comp = set()
            queue = [node]
            visited.add(node)
            while queue:
                curr = queue.pop(0)
                comp.add(curr)
                for nxt in adj[curr]:
                    if nxt not in visited:
                        visited.add(nxt)
                        queue.append(nxt)
            components.append(comp)

    is_partitioned = len(components) > 1 if alive_nodes else False
    gw_connected = any(gw in c for c in components) if alive_nodes else False
    gw_comp_size = len(next((c for c in components if gw in c), set()))

    # 2. Tarjan's algorithm for Articulation Points (Cut Vertices) and Bridges
    discovery = {}
    low = {}
    parent = {}
    time_counter = 0
    articulation_points = set()
    bridges = []

    def dfs(u):
        nonlocal time_counter
        discovery[u] = low[u] = time_counter
        time_counter += 1
        children = 0

        for v in sorted(adj[u]):
            if v not in discovery:
                parent[v] = u
                children += 1
                dfs(v)
                low[u] = min(low[u], low[v])
                # Root of DFS tree is articulation point iff it has >= 2 children
                if u not in parent and children > 1:
                    articulation_points.add(u)
                # Non-root node u is articulation point if low[v] >= discovery[u]
                if u in parent and low[v] >= discovery[u]:
                    articulation_points.add(u)
                # Bridge condition
                if low[v] > discovery[u]:
                    bridges.append((min(u, v), max(u, v)))
            elif v != parent.get(u):
                low[u] = min(low[u], discovery[v])

    for node in sorted(alive_nodes):
        if node not in discovery:
            dfs(node)

    # 3. Categorize Critical Bottlenecks (SPOF vs Gateway)
    critical_relays = sorted(articulation_points - {gw})

    # 4. Resilience Score calculation (0 to 100%)
    # - Penalty for disconnected components: -35% per disconnected component
    # - Penalty for articulation points: -12% per non-gateway articulation point
    # - Penalty for bridges: -5% per bridge
    # - Bonus for average degree > 2.5 (alternate routing paths)
    n = max(1, len(alive_nodes))
    total_edges = len(links)
    avg_degree = (2.0 * total_edges) / n if n > 0 else 0

    base_score = 100.0
    if is_partitioned:
        base_score -= 30.0 * (len(components) - 1)
    base_score -= 12.0 * len(critical_relays)
    base_score -= 4.0 * len(bridges)
    if avg_degree >= 3.0:
        base_score += 10.0
    resilience_score = max(5.0, min(100.0, round(base_score, 1)))

    # Human-readable diagnostic
    if is_partitioned:
        diagnostic = f"Network split into {len(components)} isolated segments. {len(alive_nodes) - gw_comp_size} nodes cut off from gateway."
    elif critical_relays:
        diagnostic = f"Relay {critical_relays[0]} is a single point of failure (cut-vertex); failure will split the mesh."
    elif avg_degree < 2.0:
        diagnostic = "Sparse line topology; vulnerable to single link cuts."
    else:
        diagnostic = "Biconnected mesh topology: load can share across alternate routes with no single point of failure."

    return {
        'resilience_score': resilience_score,
        'score': resilience_score,
        'articulation_points': sorted(articulation_points),
        'cut_vertices': sorted(articulation_points),
        'critical_relays': critical_relays,
        'bridges': bridges,
        'is_biconnected': len(articulation_points) == 0 and not is_partitioned,
        'is_partitioned': is_partitioned,
        'component_count': len(components),
        'avg_degree': round(avg_degree, 2),
        'diagnostic': diagnostic,
    }
