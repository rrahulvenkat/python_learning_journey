# Shortest Paths: BFS for hops, Dijkstra for costs
# (includes LeetCode 1091 Shortest Path in Binary Matrix, and
#  LeetCode 743 Network Delay Time)
#
# PROBLEM
# -------
#   1. LeetCode 1091: in a grid of 0s (open) and 1s (blocked), find the
#      length of the shortest path from the top-left to the
#      bottom-right, moving in any of 8 directions. Return -1 if there
#      isn't one.
#
#   2. In a network, find the shortest path between two machines, and
#      return the PATH itself, not just its length.
#
#   3. LeetCode 743: edges have travel TIMES. A signal is sent from one
#      node; how long until every node has received it?
#
# KEY IDEAS
# ---------
#   - When every step costs the same, BFS finds the shortest path:
#     it reaches all nodes 1 step away before any node 2 steps away,
#     so the FIRST time it reaches the target is via a shortest path.
#   - To return the path, remember each node's PARENT (the node it was
#     reached from). At the end, follow parents back from the target
#     and reverse the list.
#   - When edges have different COSTS, BFS is wrong: a 3-hop route can
#     be cheaper than a 1-hop one. DIJKSTRA'S algorithm fixes this by
#     always expanding the node with the smallest total cost so far,
#     using a min-heap (heapq, as in meeting_rooms.py).
#   - Dijkstra needs costs that are never negative.
#
# WHAT'S NEW HERE
# ---------------
# graph_basics.py found WHICH nodes were reachable. This file finds the
# BEST route, rebuilds it with a parent map, and moves from equal-cost
# steps (BFS) to weighted ones (Dijkstra).
#
# SECURITY CONNECTION
# -------------------
# ATTACK PATH ANALYSIS: model the network as a graph where each edge
# is a step an attacker could take (an open port, reused credentials,
# an unpatched service). Then:
#   - the fewest-hops path from the internet to the database shows how
#     exposed it is (BFS)
#   - giving each step a DIFFICULTY score and running Dijkstra finds
#     the EASIEST route, which is usually the one to fix first
# BloodHound does this for Active Directory ("shortest path to Domain
# Admins"). Defenders use it to find the few edges whose removal cuts
# off the most attack paths.


import heapq
from collections import deque


# ---------------------------------------------------------------
# Part 1: Shortest Path in Binary Matrix (LeetCode 1091)
# ---------------------------------------------------------------
#
# The path length counts CELLS, so a 1x1 open grid has length 1.
#
#   grid = [[0, 0, 0],
#           [1, 1, 0],
#           [1, 1, 0]]
#
#   (0,0) -> (0,1) -> (1,2) -> (2,2)     length 4 (moving diagonally once)
#
# Storing the distance WITH each queue entry means no separate
# distance table is needed.

EIGHT_DIRECTIONS = [(-1, -1), (-1, 0), (-1, 1), (0, -1),
                    (0, 1), (1, -1), (1, 0), (1, 1)]

def shortest_path_binary_matrix(grid):
    n = len(grid)
    if grid[0][0] == 1 or grid[n - 1][n - 1] == 1:
        return -1
    seen = {(0, 0)}
    queue = deque([(0, 0, 1)])                           # row, col, path length
    while queue:
        r, c, length = queue.popleft()
        if (r, c) == (n - 1, n - 1):
            return length
        for dr, dc in EIGHT_DIRECTIONS:
            r2, c2 = r + dr, c + dc
            if 0 <= r2 < n and 0 <= c2 < n and grid[r2][c2] == 0 and (r2, c2) not in seen:
                seen.add((r2, c2))
                queue.append((r2, c2, length + 1))
    return -1


# ---------------------------------------------------------------
# Part 2: fewest-hops path in a network, with the path itself
# ---------------------------------------------------------------
#
# Trace from "internet" to "db":
#
#   internet -> vpn -> jumpbox -> db
#   internet -> web -> app -> db
#   internet -> web -> db?  (no such edge)
#
#   node     | reached from
#   ---------|-------------
#   internet | (start)
#   web      | internet
#   vpn      | internet
#   app      | web
#   jumpbox  | vpn
#   db       | app          <- first time db is reached: stop
#
#   follow parents back: db <- app <- web <- internet
#   reversed: internet -> web -> app -> db

def shortest_hops(graph, start, goal):
    parent = {start: None}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        if node == goal:
            return rebuild_path(parent, goal)
        for neighbour in graph.get(node, []):
            if neighbour not in parent:                  # parent doubles as "seen"
                parent[neighbour] = node
                queue.append(neighbour)
    return None


def rebuild_path(parent, goal):
    path = []
    node = goal
    while node is not None:
        path.append(node)
        node = parent[node]
    return path[::-1]


# ---------------------------------------------------------------
# Part 3: Dijkstra's algorithm (weighted edges)
# ---------------------------------------------------------------
#
# graph[a] is a list of (b, cost). The heap holds (cost so far, node),
# so heappop always gives the cheapest node not yet finished.
#
# Why BFS fails with costs:
#
#   internet --10--> db                     1 hop,  cost 10
#   internet --2--> web --2--> app --2--> db   3 hops, cost 6   <- cheaper
#
# Trace from internet:
#
#   pop (cost, node) | update neighbours (if cheaper)  | heap after
#   -----------------|---------------------------------|--------------------
#   (0, internet)    | db = 10, web = 2                | (2,web) (10,db)
#   (2, web)         | app = 4                         | (4,app) (10,db)
#   (4, app)         | db = 6 (better than 10)         | (6,db) (10,db)
#   (6, db)          | goal reached                    |
#   (10, db) would be popped later, but db is already finished: skip it
#
# "Skip if already finished" (the `if cost > best[node]` line) is how
# this version handles old, out-of-date heap entries.

def dijkstra(graph, start):
    best = {start: 0}
    parent = {start: None}
    heap = [(0, start)]
    while heap:
        cost, node = heapq.heappop(heap)
        if cost > best[node]:
            continue                                     # an out-of-date entry
        for neighbour, step in graph.get(node, []):
            new_cost = cost + step
            if new_cost < best.get(neighbour, float("inf")):
                best[neighbour] = new_cost
                parent[neighbour] = node
                heapq.heappush(heap, (new_cost, neighbour))
    return best, parent


def cheapest_path(graph, start, goal):
    best, parent = dijkstra(graph, start)
    if goal not in best:
        return None, None
    return best[goal], rebuild_path(parent, goal)


# ---------------------------------------------------------------
# Part 4: Network Delay Time (LeetCode 743)
# ---------------------------------------------------------------
#
# times[i] = (u, v, w): a signal takes w to travel from u to v.
# Nodes are 1..n. The answer is when the LAST node receives the signal:
# the largest shortest-path cost. If any node is unreachable, -1.

def network_delay_time(times, n, k):
    graph = {i: [] for i in range(1, n + 1)}
    for u, v, w in times:
        graph[u].append((v, w))
    best, _ = dijkstra(graph, k)
    return max(best.values()) if len(best) == n else -1


# ---------------------------------------------------------------
# Part 5: which single fix removes the most risk?
# ---------------------------------------------------------------
#
# Try removing each edge on the current easiest attack path, and
# recompute. The edge whose removal makes the attacker's best route
# most expensive (or impossible) is the most valuable fix.

def best_single_fix(graph, start, goal):
    cost, path = cheapest_path(graph, start, goal)
    if path is None:
        return None
    results = []
    for a, b in zip(path, path[1:]):
        trimmed = {node: [(n, w) for n, w in edges if (node, n) != (a, b)]
                   for node, edges in graph.items()}
        new_cost, _ = cheapest_path(trimmed, start, goal)
        results.append(((a, b), new_cost))
    # None (unreachable) is the best outcome, then the highest new cost
    results.sort(key=lambda item: (item[1] is not None, -(item[1] or 0)))
    return results


# ---------------------------------------------------------------
# COMPLEXITY (V = nodes, E = edges)
# ---------------------------------------------------------------
#
#   Algorithm                     | Time               | Extra space
#   ------------------------------|--------------------|------------
#   BFS shortest path (grid)      | O(n^2) for n x n   | O(n^2)
#   BFS shortest hops + path      | O(V + E)           | O(V)
#   Dijkstra with a heap          | O((V + E) log V)   | O(V + E)
#   Network delay                 | O((V + E) log V)   | O(V + E)
#   Best single fix               | O(P * (V + E) log V), P = path length
#
# Use BFS when every step costs the same, Dijkstra when costs differ
# but are never negative. (Negative costs need Bellman-Ford, which is
# slower.)


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    # LeetCode 1091 examples
    assert shortest_path_binary_matrix([[0, 1], [1, 0]]) == 2
    assert shortest_path_binary_matrix([[0, 0, 0], [1, 1, 0], [1, 1, 0]]) == 4
    assert shortest_path_binary_matrix([[1, 0, 0], [1, 1, 0], [1, 1, 0]]) == -1
    assert shortest_path_binary_matrix([[0]]) == 1
    assert shortest_path_binary_matrix([[0, 1], [1, 1]]) == -1           # goal blocked

    # Fewest hops
    network = {
        "internet": ["web", "vpn"],
        "web": ["app"],
        "vpn": ["jumpbox"],
        "app": ["db"],
        "jumpbox": ["db", "backup"],
        "db": [],
        "backup": [],
    }
    path = shortest_hops(network, "internet", "db")
    assert len(path) == 4 and path[0] == "internet" and path[-1] == "db"
    assert shortest_hops(network, "internet", "internet") == ["internet"]
    assert shortest_hops(network, "db", "internet") is None             # directed
    assert shortest_hops(network, "internet", "backup") == ["internet", "vpn", "jumpbox", "backup"]

    # Dijkstra: the cheap 3-hop route beats the expensive 1-hop one
    weighted = {
        "internet": [("db", 10), ("web", 2)],
        "web": [("app", 2)],
        "app": [("db", 2)],
    }
    assert cheapest_path(weighted, "internet", "db") == (6, ["internet", "web", "app", "db"])
    assert shortest_hops({k: [n for n, _ in v] for k, v in weighted.items()},
                         "internet", "db") == ["internet", "db"]        # BFS ignores cost
    assert cheapest_path(weighted, "db", "internet") == (None, None)

    # Dijkstra agrees with brute force on small random graphs
    import random
    from itertools import permutations
    random.seed(11)
    for _ in range(100):
        n = random.randint(2, 6)
        g = {i: [] for i in range(n)}
        for a in range(n):
            for b in range(n):
                if a != b and random.random() < 0.4:
                    g[a].append((b, random.randint(1, 9)))
        best, _ = dijkstra(g, 0)
        for target in range(1, n):
            # brute force: try every simple path from 0 to target
            cheapest = None
            others = [x for x in range(n) if x not in (0, target)]
            for k in range(len(others) + 1):
                for middle in permutations(others, k):
                    route = (0,) + middle + (target,)
                    total = 0
                    for a, b in zip(route, route[1:]):
                        weights = [w for nb, w in g[a] if nb == b]
                        if not weights:
                            break
                        total += min(weights)
                    else:
                        cheapest = total if cheapest is None else min(cheapest, total)
            assert best.get(target) == cheapest, (g, target)

    # LeetCode 743 examples
    assert network_delay_time([[2, 1, 1], [2, 3, 1], [3, 4, 1]], 4, 2) == 2
    assert network_delay_time([[1, 2, 1]], 2, 1) == 1
    assert network_delay_time([[1, 2, 1]], 2, 2) == -1

    # Best single fix
    attack = {
        "internet": [("web", 1), ("vpn", 4)],
        "web": [("app", 1)],
        "vpn": [("app", 2)],
        "app": [("db", 1)],
    }
    fixes = best_single_fix(attack, "internet", "db")
    assert fixes[0] == (("app", "db"), None)                            # cuts every path
    assert dict(fixes)[("internet", "web")] == 7                        # forces the VPN route

    print("All tests passed!")


if __name__ == "__main__":
    grid = [[0, 0, 0], [1, 1, 0], [1, 1, 0]]
    print(f"Shortest path through {grid}: {shortest_path_binary_matrix(grid)} cells")

    # Attack graph: each edge is a step, with a difficulty score
    # (1 = trivial, 10 = very hard)
    # svc-account is a shared credential that three different routes
    # pass through, so it's the bottleneck to look for.
    attack = {
        "internet":    [("vpn", 7), ("web-server", 2), ("phish-email", 3)],
        "phish-email": [("hr-laptop", 2)],
        "web-server":  [("app-server", 8)],
        "vpn":         [("jumpbox", 2)],
        "hr-laptop":   [("file-share", 1), ("jumpbox", 6)],
        "file-share":  [("svc-account", 2)],
        "app-server":  [("svc-account", 1), ("db-prod", 3)],
        "jumpbox":     [("svc-account", 1), ("db-prod", 6)],
        "svc-account": [("db-prod", 1)],
    }
    hop_graph = {k: [n for n, _ in v] for k, v in attack.items()}

    print("\nAttack graph, from the internet to db-prod:")
    hops = shortest_hops(hop_graph, "internet", "db-prod")
    print(f"  fewest hops ({len(hops) - 1}):  {' -> '.join(hops)}")
    cost, easiest = cheapest_path(attack, "internet", "db-prod")
    print(f"  easiest route (difficulty {cost}): {' -> '.join(easiest)}")

    print("\nRemoving each step of the easiest route:")
    for (a, b), new_cost in best_single_fix(attack, "internet", "db-prod"):
        outcome = "db-prod unreachable" if new_cost is None else f"easiest route now costs {new_cost}"
        print(f"  block {a} -> {b}: {outcome}")

    print(f"\nNetwork delay (LeetCode 743 example): "
          f"{network_delay_time([[2, 1, 1], [2, 3, 1], [3, 4, 1]], 4, 2)}")

    print()
    run_tests()
