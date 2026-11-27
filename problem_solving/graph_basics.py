# Graph Basics: representations, BFS, DFS and connected components
# (includes LeetCode 1971 Find if Path Exists, and LeetCode 547 Number of Provinces)
#
# WHAT A GRAPH IS
# ---------------
# A graph is a set of NODES (also called vertices) joined by EDGES.
#   - Undirected: an edge works both ways (a network cable, a friendship)
#   - Directed:   an edge has a direction (a firewall rule "A may connect
#                 to B", a web link, "user X is admin on host Y")
#   - Weighted:   each edge has a cost (latency, difficulty to exploit);
#                 see shortest_path.py
#
# Lists, trees and grids are all special kinds of graphs.
#
# KEY IDEAS
# ---------
#   - Store a graph as an ADJACENCY LIST: a dictionary mapping each node
#     to its neighbours. It's compact and makes "who are my neighbours?"
#     O(1) to look up.
#   - BFS (breadth-first search) explores in RINGS: all nodes 1 step
#     away, then 2 steps, then 3. It uses a QUEUE (collections.deque).
#     BFS finds the FEWEST-HOPS path.
#   - DFS (depth-first search) follows one path as far as it can, then
#     backs up. It uses a STACK, or recursion (the call stack). It's the
#     same "go deep, then backtrack" idea as subsets.py.
#   - Both need a VISITED set. Graphs can have cycles (A -> B -> A), and
#     without `visited` the search loops forever.
#
# WHAT'S NEW HERE
# ---------------
# Everything so far worked on lists, strings and grids of numbers. A
# graph is the first structure where items are connected in an
# arbitrary pattern. The queue from data_structures/lists.py drives BFS,
# and the stack from valid_parentheses.py drives DFS.
#
# SECURITY CONNECTION
# -------------------
# A network is a graph. After an attacker compromises ONE machine, the
# question is "what else can they reach from here?" That's a BFS or DFS
# from the compromised node, called LATERAL MOVEMENT analysis. Connected
# components answer "are these network segments really isolated from
# each other?" Tools like BloodHound model Active Directory as a graph
# and run exactly these searches.


from collections import deque


# ---------------------------------------------------------------
# Part 1: three ways to store a graph
# ---------------------------------------------------------------
#
# The same small network, undirected:
#
#     web ---- app ---- db
#      |        |
#     dmz      cache
#
#   EDGE LIST          [("web", "app"), ("app", "db"), ("web", "dmz"), ("app", "cache")]
#                      simple, but finding a node's neighbours means scanning everything
#
#   ADJACENCY LIST     {"web": ["app", "dmz"], "app": ["web", "db", "cache"], ...}
#                      the usual choice
#
#   ADJACENCY MATRIX   a table where matrix[i][j] = 1 if node i links to node j
#                      O(1) to check one edge, but n * n memory even when
#                      there are few edges
#
#   representation   | memory     | neighbours of x | is there an edge x-y?
#   -----------------|------------|-----------------|----------------------
#   edge list        | O(E)       | O(E)            | O(E)
#   adjacency list   | O(V + E)   | O(1) to get     | O(degree of x)
#   adjacency matrix | O(V^2)     | O(V)            | O(1)
#
#   V = number of nodes (vertices), E = number of edges

def build_graph(edges, directed=False):
    graph = {}
    for a, b in edges:
        graph.setdefault(a, []).append(b)
        graph.setdefault(b, [])                    # make sure b exists as a node
        if not directed:
            graph[b].append(a)
    return graph


def to_matrix(graph):
    nodes = sorted(graph)
    index = {node: i for i, node in enumerate(nodes)}
    matrix = [[0] * len(nodes) for _ in nodes]
    for node, neighbours in graph.items():
        for other in neighbours:
            matrix[index[node]][index[other]] = 1
    return nodes, matrix


# ---------------------------------------------------------------
# Part 2: BFS (breadth-first search)
# ---------------------------------------------------------------
#
# Trace from "web" on the network above:
#
#   queue (front first)    | visit | add to queue (not seen before)
#   -----------------------|-------|-------------------------------
#   [web]                  | web   | app, dmz
#   [app, dmz]             | app   | db, cache   (web is already seen)
#   [dmz, db, cache]       | dmz   | -
#   [db, cache]            | db    | -
#   [cache]                | cache | -
#
#   order: web, app, dmz, db, cache    (1 hop: app, dmz; 2 hops: db, cache)
#
# Mark a node as seen when it's ADDED to the queue, not when it's
# visited. Otherwise the same node can be added several times.

def bfs(graph, start):
    seen = {start}
    queue = deque([start])
    order = []
    while queue:
        node = queue.popleft()                     # FIFO: oldest first
        order.append(node)
        for neighbour in graph[node]:
            if neighbour not in seen:
                seen.add(neighbour)
                queue.append(neighbour)
    return order


# BFS also gives every node's DISTANCE (number of hops) from the start.
def bfs_distances(graph, start):
    distance = {start: 0}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for neighbour in graph[node]:
            if neighbour not in distance:
                distance[neighbour] = distance[node] + 1
                queue.append(neighbour)
    return distance


# ---------------------------------------------------------------
# Part 3: DFS (depth-first search), two ways
# ---------------------------------------------------------------
#
# Recursive: visit a node, then fully explore each neighbour before the
# next one.
#
#   from web: web -> app -> db (dead end, back up) -> cache (back up)
#             -> back to web -> dmz
#   order: web, app, db, cache, dmz
#
# Recursion depth equals the longest path explored, so a long chain of
# nodes can hit Python's recursion limit (about 1,000). The iterative
# version with an explicit stack has no such limit.

def dfs_recursive(graph, start, seen=None, order=None):
    if seen is None:
        seen, order = set(), []
    seen.add(start)
    order.append(start)
    for neighbour in graph[start]:
        if neighbour not in seen:
            dfs_recursive(graph, neighbour, seen, order)
    return order


# Iterative: the same thing with a list as a stack. Neighbours are
# pushed in REVERSE so the first neighbour is popped first, which
# gives the same order as the recursive version.

def dfs_iterative(graph, start):
    seen = set()
    stack = [start]
    order = []
    while stack:
        node = stack.pop()                         # LIFO: newest first
        if node in seen:
            continue
        seen.add(node)
        order.append(node)
        for neighbour in reversed(graph[node]):
            if neighbour not in seen:
                stack.append(neighbour)
    return order


# ---------------------------------------------------------------
# Part 4: Find if Path Exists (LeetCode 1971)
# ---------------------------------------------------------------
#
# Is there any path from source to destination? Run BFS from source and
# stop as soon as destination appears.

def valid_path(n, edges, source, destination):
    graph = {i: [] for i in range(n)}
    for a, b in edges:
        graph[a].append(b)
        graph[b].append(a)

    seen = {source}
    queue = deque([source])
    while queue:
        node = queue.popleft()
        if node == destination:
            return True
        for neighbour in graph[node]:
            if neighbour not in seen:
                seen.add(neighbour)
                queue.append(neighbour)
    return False


# ---------------------------------------------------------------
# Part 5: connected components (LeetCode 547, Number of Provinces)
# ---------------------------------------------------------------
#
# A COMPONENT is a group of nodes that can all reach each other. To
# count them: for every node not seen yet, start a new search from it.
# Each new search is one new component.
#
# LeetCode 547 gives the graph as an adjacency matrix:
#   [[1, 1, 0],
#    [1, 1, 0],      cities 0 and 1 are connected, city 2 is alone
#    [0, 0, 1]]  ->  2 provinces

def find_circle_num(matrix):
    n = len(matrix)
    seen = set()
    provinces = 0
    for city in range(n):
        if city in seen:
            continue
        provinces += 1                             # a new component
        stack = [city]
        seen.add(city)
        while stack:
            current = stack.pop()
            for other in range(n):
                if matrix[current][other] and other not in seen:
                    seen.add(other)
                    stack.append(other)
    return provinces


def components(graph):
    seen = set()
    groups = []
    for node in graph:
        if node not in seen:
            group = bfs(graph, node)
            seen.update(group)
            groups.append(sorted(group))
    return groups


# ---------------------------------------------------------------
# Part 6: lateral movement from a compromised host
# ---------------------------------------------------------------
#
# The graph is DIRECTED: an edge A -> B means "from A you can connect
# to B" (an allowed firewall rule, or reused credentials). BFS from the
# compromised host lists everything an attacker could reach, and how
# many hops away each one is.

def reachable_from(graph, compromised):
    distances = bfs_distances(graph, compromised)
    del distances[compromised]
    return dict(sorted(distances.items(), key=lambda item: (item[1], item[0])))


# ---------------------------------------------------------------
# COMPLEXITY (V = nodes, E = edges)
# ---------------------------------------------------------------
#
#   Algorithm              | Time       | Extra space
#   -----------------------|------------|-------------------------
#   Build adjacency list   | O(V + E)   | O(V + E)
#   BFS / DFS              | O(V + E)   | O(V) for seen + queue/stack
#   Path exists            | O(V + E)   | O(V)
#   Components (list)      | O(V + E)   | O(V)
#   Provinces (matrix)     | O(V^2)     | O(V)   the matrix has V^2 cells
#
# Every node is visited once, and every edge is looked at once (twice
# if undirected), which is where V + E comes from.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

NETWORK_EDGES = [("web", "app"), ("app", "db"), ("web", "dmz"), ("app", "cache")]


def run_tests():
    graph = build_graph(NETWORK_EDGES)
    assert graph["app"] == ["web", "db", "cache"]
    assert graph["dmz"] == ["web"]

    directed = build_graph([("a", "b"), ("b", "c")], directed=True)
    assert directed == {"a": ["b"], "b": ["c"], "c": []}

    nodes, matrix = to_matrix(graph)
    i, j = nodes.index("web"), nodes.index("app")
    assert matrix[i][j] == matrix[j][i] == 1
    assert sum(map(sum, matrix)) == 2 * len(NETWORK_EDGES)       # undirected: both ways

    # Traversal orders
    assert bfs(graph, "web") == ["web", "app", "dmz", "db", "cache"]
    assert dfs_recursive(graph, "web") == ["web", "app", "db", "cache", "dmz"]
    assert dfs_iterative(graph, "web") == dfs_recursive(graph, "web")
    assert bfs_distances(graph, "web") == {"web": 0, "app": 1, "dmz": 1, "db": 2, "cache": 2}

    # Cycles don't cause infinite loops
    cycle = build_graph([(1, 2), (2, 3), (3, 1), (3, 4)])
    assert sorted(bfs(cycle, 1)) == [1, 2, 3, 4]
    assert sorted(dfs_iterative(cycle, 4)) == [1, 2, 3, 4]

    # A long chain: the iterative DFS is fine where recursion would fail
    chain = build_graph([(i, i + 1) for i in range(5_000)])
    assert len(dfs_iterative(chain, 0)) == 5_001

    # LeetCode 1971
    assert valid_path(3, [[0, 1], [1, 2], [2, 0]], 0, 2) is True
    assert valid_path(6, [[0, 1], [0, 2], [3, 5], [5, 4], [4, 3]], 0, 5) is False
    assert valid_path(1, [], 0, 0) is True

    # LeetCode 547
    assert find_circle_num([[1, 1, 0], [1, 1, 0], [0, 0, 1]]) == 2
    assert find_circle_num([[1, 0, 0], [0, 1, 0], [0, 0, 1]]) == 3
    assert find_circle_num([[1]]) == 1

    # Components
    segmented = build_graph([("a", "b"), ("b", "c"), ("x", "y")])
    segmented["lonely"] = []
    assert components(segmented) == [["a", "b", "c"], ["x", "y"], ["lonely"]]

    # Lateral movement (directed)
    access = build_graph([
        ("laptop", "fileserver"), ("laptop", "jumpbox"),
        ("jumpbox", "db"), ("jumpbox", "backup"), ("db", "backup"),
        ("hr-pc", "payroll"),
    ], directed=True)
    assert reachable_from(access, "laptop") == {
        "fileserver": 1, "jumpbox": 1, "backup": 2, "db": 2}
    assert reachable_from(access, "db") == {"backup": 1}
    assert reachable_from(access, "payroll") == {}

    print("All tests passed!")


if __name__ == "__main__":
    graph = build_graph(NETWORK_EDGES)
    print("Adjacency list:")
    for node, neighbours in graph.items():
        print(f"  {node:<6} -> {neighbours}")

    nodes, matrix = to_matrix(graph)
    print("\nAdjacency matrix:")
    print("        " + " ".join(f"{n:>5}" for n in nodes))
    for name, row in zip(nodes, matrix):
        print(f"  {name:<5} " + " ".join(f"{v:>5}" for v in row))

    print(f"\nBFS from web: {bfs(graph, 'web')}")
    print(f"DFS from web: {dfs_recursive(graph, 'web')}")

    # Which machines can an attacker reach after phishing one laptop?
    access = build_graph([
        ("laptop-17", "fileserver"), ("laptop-17", "jumpbox"),
        ("jumpbox", "db-prod"), ("jumpbox", "backup"), ("db-prod", "backup"),
        ("fileserver", "printer"), ("hr-pc", "payroll"),
    ], directed=True)
    print("\nLaptop-17 was phished. Reachable from it:")
    for host, hops in reachable_from(access, "laptop-17").items():
        print(f"  {host:<11} {hops} hop{'s' if hops > 1 else ''}")
    unreached = sorted(set(access) - set(reachable_from(access, "laptop-17")) - {"laptop-17"})
    print(f"  not reachable: {unreached}")

    undirected = build_graph([(a, b) for a, nbrs in access.items() for b in nbrs])
    print(f"\nNetwork segments (connected components): {components(undirected)}")

    print()
    run_tests()
