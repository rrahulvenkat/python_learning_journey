# Clone Graph (LeetCode 133), cycle detection and topological sort
# (includes LeetCode 207 Course Schedule, and LeetCode 210 Course Schedule II)
#
# PROBLEM
# -------
#   1. Clone Graph: given one node of a connected, undirected graph,
#      return a DEEP COPY: brand-new node objects with the same values
#      and the same connections. No node in the copy may be an
#      original.
#
#   2. Course Schedule: given courses and prerequisites ("to take B
#      you must finish A"), can every course be finished? If so, in
#      what order?
#
# KEY IDEAS
# ---------
#   - Cloning: the graph can have CYCLES (1 - 2 - 3 - 1), so a naive
#     recursive copy would loop forever. Keep a dictionary
#     {original node: its copy}. It does two jobs at once:
#       * it's the VISITED set (if a node is in it, it's done)
#       * it lets you connect each copy to the copies of its neighbours
#     This "map old to new" pattern is how copy.deepcopy works.
#   - Course Schedule is a DIRECTED graph. Every course can be finished
#     only if there's NO CYCLE (A needs B, B needs C, C needs A).
#   - TOPOLOGICAL SORT gives an order where every node comes after all
#     the nodes it depends on. Kahn's algorithm: repeatedly take a node
#     with NO remaining prerequisites (in-degree 0), and remove its
#     edges. If some nodes are never freed, there's a cycle.
#   - DFS can also find cycles using three colours:
#       WHITE = not visited, GREY = on the current path, BLACK = done
#     Reaching a GREY node means you've gone in a circle.
#
# WHAT'S NEW HERE
# ---------------
# graph_basics.py used nodes that were just names in a dictionary.
# Here nodes are OBJECTS (a small class) that hold references to each
# other, the way real data structures do. And it's the first time the
# DIRECTION of edges really matters.
#
# SECURITY CONNECTION
# -------------------
#   - PATCH ORDER: services depend on each other (the app needs the
#     database, the database needs storage). A topological sort gives a
#     safe order to restart them after patching.
#   - SUPPLY CHAIN: a package's dependencies form a directed graph.
#     Walking it finds every package a vulnerability (like Log4Shell
#     in log4j, 2021) affects, including indirect dependencies
#     (variation 2).
#   - Cycles in permission or trust relationships ("A trusts B trusts
#     C trusts A") can let access loop back in unexpected ways.


from collections import deque


# ---------------------------------------------------------------
# The node class LeetCode uses
# ---------------------------------------------------------------

class Node:
    def __init__(self, val=0, neighbors=None):
        self.val = val
        self.neighbors = neighbors if neighbors is not None else []

    def __repr__(self):
        return f"Node({self.val})"


def build_from_adjacency(adjacency):
    """LeetCode's format: adjacency[i] lists the neighbours of node i + 1."""
    if not adjacency:
        return None
    nodes = [Node(i + 1) for i in range(len(adjacency))]
    for i, neighbour_vals in enumerate(adjacency):
        nodes[i].neighbors = [nodes[v - 1] for v in neighbour_vals]
    return nodes[0]


def to_adjacency(node):
    """Turn a graph back into LeetCode's format, to compare graphs."""
    if node is None:
        return []
    seen = {}
    stack = [node]
    while stack:
        current = stack.pop()
        if current.val in seen:
            continue
        seen[current.val] = current
        stack.extend(current.neighbors)
    return [[n.val for n in seen[v].neighbors] for v in sorted(seen)]


def all_nodes(node):
    seen, stack = set(), [node]
    while stack:
        current = stack.pop()
        if id(current) not in seen:
            seen.add(id(current))
            stack.extend(current.neighbors)
            yield current


# ---------------------------------------------------------------
# Clone Graph, solution 1: DFS with an "original -> copy" map
# ---------------------------------------------------------------
#
# Trace for the square 1 - 2 - 3 - 4 - 1:
#
#   clone(1): make 1', copies = {1: 1'}
#     clone(2): make 2', copies = {1: 1', 2: 2'}
#       neighbour 1 is already copied -> link 2' to 1'
#       clone(3): make 3' ... clone(4): make 4'
#         neighbour 1 is already copied -> link 4' to 1'   (no loop!)
#
# The copy is stored BEFORE its neighbours are cloned. That's what
# stops the cycle: when the search comes back round, it finds the copy
# already exists.

def clone_graph_dfs(node):
    copies = {}

    def clone(original):
        if original in copies:
            return copies[original]
        copy = Node(original.val)
        copies[original] = copy                          # store first, then recurse
        copy.neighbors = [clone(n) for n in original.neighbors]
        return copy

    return clone(node) if node else None


# ---------------------------------------------------------------
# Clone Graph, solution 2: BFS (no recursion limit)
# ---------------------------------------------------------------

def clone_graph_bfs(node):
    if node is None:
        return None
    copies = {node: Node(node.val)}
    queue = deque([node])
    while queue:
        original = queue.popleft()
        for neighbour in original.neighbors:
            if neighbour not in copies:
                copies[neighbour] = Node(neighbour.val)
                queue.append(neighbour)
            copies[original].neighbors.append(copies[neighbour])
    return copies[node]


# ---------------------------------------------------------------
# Course Schedule, solution 1: Kahn's algorithm (BFS topological sort)
# ---------------------------------------------------------------
#
# prerequisites [b, a] means "a must come before b" (edge a -> b).
#
# Example: 4 courses, prerequisites [[1, 0], [2, 0], [3, 1], [3, 2]]
#
#   0 -> 1 -> 3
#   0 -> 2 -> 3
#
#   in-degree (number of prerequisites): 0:0  1:1  2:1  3:2
#
#   queue | take | order so far | in-degrees after removing its edges
#   ------|------|--------------|------------------------------------
#   [0]   |  0   | [0]          | 1:0  2:0       -> add 1, 2
#   [1,2] |  1   | [0, 1]       | 3:1
#   [2]   |  2   | [0, 1, 2]    | 3:0            -> add 3
#   [3]   |  3   | [0, 1, 2, 3]
#
# All 4 courses were taken, so there's no cycle. If the order is
# shorter than the number of courses, the missing ones are stuck in a
# cycle.

def find_order(num_courses, prerequisites):
    graph = {c: [] for c in range(num_courses)}
    in_degree = [0] * num_courses
    for course, before in prerequisites:
        graph[before].append(course)
        in_degree[course] += 1

    queue = deque(c for c in range(num_courses) if in_degree[c] == 0)
    order = []
    while queue:
        course = queue.popleft()
        order.append(course)
        for nxt in graph[course]:
            in_degree[nxt] -= 1
            if in_degree[nxt] == 0:
                queue.append(nxt)

    return order if len(order) == num_courses else []


def can_finish(num_courses, prerequisites):
    return len(find_order(num_courses, prerequisites)) == num_courses


# ---------------------------------------------------------------
# Course Schedule, solution 2: DFS with three colours
# ---------------------------------------------------------------
#
# GREY means "on the path I'm exploring right now". Reaching a GREY
# node again means following edges led back to where we are: a cycle.
# BLACK nodes are finished and known to be safe, so they're skipped.
# This version also returns the cycle, which is far more useful than
# just "False".

WHITE, GREY, BLACK = 0, 1, 2

def find_cycle(graph):
    color = {node: WHITE for node in graph}
    path = []

    def visit(node):
        color[node] = GREY
        path.append(node)
        for nxt in graph[node]:
            if color[nxt] == GREY:                       # back to the current path
                return path[path.index(nxt):] + [nxt]
            if color[nxt] == WHITE:
                cycle = visit(nxt)
                if cycle:
                    return cycle
        path.pop()
        color[node] = BLACK
        return None

    for node in graph:
        if color[node] == WHITE:
            cycle = visit(node)
            if cycle:
                return cycle
    return None


# ---------------------------------------------------------------
# Variation 1: a safe restart order for dependent services
# ---------------------------------------------------------------
#
# depends_on[x] lists what x needs running first. Returns an order to
# start them, or raises an error showing the circular dependency.

def startup_order(depends_on):
    services = set(depends_on) | {d for deps in depends_on.values() for d in deps}
    graph = {s: [] for s in sorted(services)}
    for service, deps in depends_on.items():
        for dep in deps:
            graph[dep].append(service)                   # dep must start before service

    cycle = find_cycle(graph)
    if cycle:
        raise ValueError("circular dependency (each must start before the next): "
                         + " -> ".join(cycle))

    names = sorted(services)
    index = {name: i for i, name in enumerate(names)}
    edges = [[index[s], index[d]] for s, deps in depends_on.items() for d in deps]
    return [names[i] for i in find_order(len(names), edges)]


# ---------------------------------------------------------------
# Variation 2: everything affected by a vulnerable package
# ---------------------------------------------------------------
#
# requires[p] lists the packages p uses directly. Flip the edges
# ("who uses me?") and BFS from the vulnerable package to find every
# package that uses it directly OR indirectly.

def affected_by(requires, vulnerable):
    used_by = {}
    for package, deps in requires.items():
        for dep in deps:
            used_by.setdefault(dep, []).append(package)

    affected = {}
    queue = deque([(vulnerable, 0)])
    while queue:
        package, depth = queue.popleft()
        for user in used_by.get(package, []):
            if user not in affected:
                affected[user] = depth + 1               # 1 = direct, 2+ = indirect
                queue.append((user, depth + 1))
    return affected


# ---------------------------------------------------------------
# COMPLEXITY (V = nodes, E = edges)
# ---------------------------------------------------------------
#
#   Algorithm                  | Time       | Extra space
#   ---------------------------|------------|-------------------------
#   Clone graph (DFS or BFS)   | O(V + E)   | O(V) the copies map
#   Kahn's topological sort    | O(V + E)   | O(V + E)
#   Three-colour cycle search  | O(V + E)   | O(V)
#   Affected packages (BFS)    | O(V + E)   | O(V + E)


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    # Clone Graph (LeetCode 133 examples)
    for adjacency in [[[2, 4], [1, 3], [2, 4], [1, 3]],          # example 1: a square
                      [[]],                                       # example 2: one node
                      [],                                         # example 3: empty
                      [[2, 3], [1, 3], [1, 2]]]:                  # a triangle
        for solve in [clone_graph_dfs, clone_graph_bfs]:
            original = build_from_adjacency(adjacency)
            copy = solve(original)
            assert to_adjacency(copy) == adjacency, (solve.__name__, adjacency)
            if original:
                originals = {id(n) for n in all_nodes(original)}
                assert all(id(n) not in originals for n in all_nodes(copy)), \
                    "the clone shares nodes with the original"

    # Changing the copy must not change the original
    original = build_from_adjacency([[2], [1]])
    copy = clone_graph_bfs(original)
    copy.val = 99
    assert original.val == 1

    # Course Schedule (LeetCode 207 and 210 examples)
    assert can_finish(2, [[1, 0]]) is True
    assert can_finish(2, [[1, 0], [0, 1]]) is False
    order = find_order(4, [[1, 0], [2, 0], [3, 1], [3, 2]])
    assert order in ([0, 1, 2, 3], [0, 2, 1, 3])
    assert find_order(1, []) == [0]
    assert find_order(3, [[1, 0], [2, 1], [0, 2]]) == []

    # Every valid order really respects the prerequisites
    prereqs = [[1, 0], [2, 0], [3, 1], [4, 3], [4, 2], [5, 4]]
    order = find_order(6, prereqs)
    position = {c: i for i, c in enumerate(order)}
    assert all(position[before] < position[course] for course, before in prereqs)

    # Cycle finding
    assert find_cycle({"a": ["b"], "b": ["c"], "c": ["a"]}) == ["a", "b", "c", "a"]
    assert find_cycle({"a": ["b"], "b": ["c"], "c": []}) is None
    assert find_cycle({"x": ["x"]}) == ["x", "x"]                 # a self-loop

    # Startup order
    deps = {"app": ["db", "cache"], "db": ["storage"], "cache": [], "web": ["app"]}
    order = startup_order(deps)
    assert order.index("storage") < order.index("db") < order.index("app") < order.index("web")
    assert order.index("cache") < order.index("app")
    try:
        startup_order({"a": ["b"], "b": ["a"]})
        assert False, "expected ValueError"
    except ValueError as err:
        assert "->" in str(err)

    # Affected packages
    requires = {
        "webapp": ["framework", "logging-lib"],
        "framework": ["http-lib"],
        "logging-lib": ["log4x"],
        "metrics": ["log4x"],
        "dashboard": ["metrics", "framework"],
    }
    assert affected_by(requires, "log4x") == {
        "logging-lib": 1, "metrics": 1, "webapp": 2, "dashboard": 2}
    assert affected_by(requires, "webapp") == {}

    print("All tests passed!")


if __name__ == "__main__":
    original = build_from_adjacency([[2, 4], [1, 3], [2, 4], [1, 3]])
    copy = clone_graph_bfs(original)
    print(f"Original: {to_adjacency(original)}")
    print(f"Clone:    {to_adjacency(copy)}")
    print(f"Same node objects? {original is copy}")

    print("\nCourse Schedule: 4 courses, [[1,0],[2,0],[3,1],[3,2]]")
    print(f"  order: {find_order(4, [[1, 0], [2, 0], [3, 1], [3, 2]])}")
    print(f"  with a cycle [[1,0],[0,1]]: can finish? {can_finish(2, [[1, 0], [0, 1]])}")

    deps = {
        "web-frontend": ["api"],
        "api": ["auth", "db", "cache"],
        "auth": ["db", "secrets-vault"],
        "db": ["storage"],
        "cache": [],
        "storage": [],
        "secrets-vault": ["storage"],
    }
    print("\nSafe restart order after patching:")
    for step, service in enumerate(startup_order(deps), start=1):
        print(f"  {step}. {service}")

    try:
        startup_order({**deps, "storage": ["auth"]})
    except ValueError as err:
        print(f"\nAfter a bad config change: {err}")

    requires = {
        "payments-service": ["web-framework", "audit-logger"],
        "web-framework": ["http-parser"],
        "audit-logger": ["log4x"],
        "metrics-agent": ["log4x"],
        "admin-portal": ["metrics-agent", "web-framework"],
        "mobile-api": ["payments-service"],
    }
    print("\nA vulnerability is found in 'log4x'. Affected:")
    for package, depth in sorted(affected_by(requires, "log4x").items(), key=lambda x: x[1]):
        kind = "direct" if depth == 1 else f"indirect, {depth} levels"
        print(f"  {package:<17} ({kind})")

    print()
    run_tests()
