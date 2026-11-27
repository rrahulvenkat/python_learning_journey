# Number of Islands (LeetCode 200)  -  grids as graphs
# (includes LeetCode 733 Flood Fill, and LeetCode 695 Max Area of Island)
#
# PROBLEM
# -------
# A grid holds "1" (land) and "0" (water). An ISLAND is a group of land
# cells joined up, down, left or right (not diagonally). Count the
# islands.
#
#   1 1 0 0 0
#   1 1 0 0 0
#   0 0 1 0 0      ->  3 islands
#   0 0 0 1 1
#
# KEY IDEAS
# ---------
#   - A grid IS a graph: every cell is a node, and each cell's edges go
#     to its (up to) 4 neighbours. You never build the graph; you work
#     out the neighbours as you go:
#         for dr, dc in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
#             r2, c2 = r + dr, c + dc
#     and check (r2, c2) is still INSIDE the grid.
#   - Counting islands is counting CONNECTED COMPONENTS
#     (graph_basics.py): scan every cell, and each time you find land
#     you haven't seen, that's a new island. Flood out from it (BFS or
#     DFS) to mark the whole island as seen.
#   - "Seen" can be a set of (row, col), or you can change the cell
#     itself ("1" -> "0") to save memory. Changing the input is a SIDE
#     EFFECT, so these solutions work on a copy.
#
# WHAT'S NEW HERE
# ---------------
# Neighbours computed from coordinates instead of stored in a
# dictionary, and bounds checking. Grid problems are some of the most
# common BFS/DFS interview questions.
#
# SECURITY CONNECTION
# -------------------
# Grids show up as maps of data: a heat map of failed logins (hour of
# day x day of week), a rack layout of servers, or the pixels of an
# image. "Find the connected hot region" is the same flood fill.
# Example: in an hours x hosts grid of alerts, a large connected
# block often means one campaign spreading across machines over time
# (variation 2). More importantly, the neighbour and visited patterns
# here are exactly what network searches in graph_basics.py and
# shortest_path.py use.


from collections import deque


DIRECTIONS = [(-1, 0), (1, 0), (0, -1), (0, 1)]          # up, down, left, right


def neighbours(grid, r, c):
    for dr, dc in DIRECTIONS:
        r2, c2 = r + dr, c + dc
        if 0 <= r2 < len(grid) and 0 <= c2 < len(grid[0]):
            yield r2, c2


# ---------------------------------------------------------------
# Solution 1: DFS, recursive
# ---------------------------------------------------------------
#
# Trace for the grid above (scanning row by row):
#
#   cell   | land, unseen? | action
#   -------|---------------|-------------------------------------------
#   (0,0)  | yes           | islands = 1; sink (0,0) (0,1) (1,0) (1,1)
#   (0,1)  | already sunk  |
#   (2,2)  | yes           | islands = 2; sink (2,2)
#   (3,3)  | yes           | islands = 3; sink (3,3) (3,4)
#
# Big islands mean deep recursion, so very large grids can hit the
# recursion limit. Solutions 2 and 3 avoid that.

def num_islands_dfs(grid):
    grid = [list(row) for row in grid]                   # work on a copy

    def sink(r, c):
        grid[r][c] = "0"
        for r2, c2 in neighbours(grid, r, c):
            if grid[r2][c2] == "1":
                sink(r2, c2)

    count = 0
    for r in range(len(grid)):
        for c in range(len(grid[0])):
            if grid[r][c] == "1":
                count += 1
                sink(r, c)
    return count


# ---------------------------------------------------------------
# Solution 2: BFS with a queue and a seen set
# ---------------------------------------------------------------

def num_islands_bfs(grid):
    if not grid:
        return 0
    seen = set()
    count = 0
    for r in range(len(grid)):
        for c in range(len(grid[0])):
            if grid[r][c] != "1" or (r, c) in seen:
                continue
            count += 1
            seen.add((r, c))
            queue = deque([(r, c)])
            while queue:
                cr, cc = queue.popleft()
                for r2, c2 in neighbours(grid, cr, cc):
                    if grid[r2][c2] == "1" and (r2, c2) not in seen:
                        seen.add((r2, c2))
                        queue.append((r2, c2))
    return count


# ---------------------------------------------------------------
# Solution 3: union-find (disjoint set union)
# ---------------------------------------------------------------
#
# A different technique for components. Every land cell starts as its
# own group. For each pair of neighbouring land cells, MERGE their
# groups. The answer is how many groups are left.
#
# `parent` points each cell towards its group's representative ("root").
# find() follows the pointers to the root; union() joins two roots.
# PATH COMPRESSION (pointing cells straight at the root as you go)
# makes this almost O(1) per operation.
#
# Union-find shines when connections arrive ONE AT A TIME (for
# example, "after each new firewall rule, how many segments are
# there?"), because it never has to search from scratch.

def num_islands_union_find(grid):
    parent = {}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]                # path compression
            x = parent[x]
        return x

    def union(a, b):
        root_a, root_b = find(a), find(b)
        if root_a != root_b:
            parent[root_b] = root_a
            return True
        return False

    for r, row in enumerate(grid):
        for c, cell in enumerate(row):
            if cell == "1":
                parent[(r, c)] = (r, c)

    groups = len(parent)
    for r, c in list(parent):
        for r2, c2 in ((r + 1, c), (r, c + 1)):          # down and right are enough
            if (r2, c2) in parent and union((r, c), (r2, c2)):
                groups -= 1
    return groups


# ---------------------------------------------------------------
# Variation 1: Flood Fill (LeetCode 733)
# ---------------------------------------------------------------
#
# Starting from (sr, sc), change that cell and every connected cell of
# the SAME colour to the new colour (the paint-bucket tool).
#
# Edge case: if the new colour equals the old one, return straight
# away, or the search never knows which cells it has already done.

def flood_fill(image, sr, sc, color):
    image = [list(row) for row in image]
    old = image[sr][sc]
    if old == color:
        return image
    queue = deque([(sr, sc)])
    image[sr][sc] = color
    while queue:
        r, c = queue.popleft()
        for r2, c2 in neighbours(image, r, c):
            if image[r2][c2] == old:
                image[r2][c2] = color                    # changing it marks it seen
                queue.append((r2, c2))
    return image


# ---------------------------------------------------------------
# Variation 2: Max Area of Island (LeetCode 695)
# ---------------------------------------------------------------
#
# Same scan, but count the cells in each island and keep the biggest.
# Returning the cells too lets the demo point at the largest region.

def largest_region(grid, is_hot=lambda v: v == 1):
    seen = set()
    best = []
    for r in range(len(grid)):
        for c in range(len(grid[0])):
            if not is_hot(grid[r][c]) or (r, c) in seen:
                continue
            region = []
            seen.add((r, c))
            stack = [(r, c)]
            while stack:
                cell = stack.pop()
                region.append(cell)
                for r2, c2 in neighbours(grid, *cell):
                    if is_hot(grid[r2][c2]) and (r2, c2) not in seen:
                        seen.add((r2, c2))
                        stack.append((r2, c2))
            if len(region) > len(best):
                best = region
    return best


def max_area_of_island(grid):
    return len(largest_region(grid))


# ---------------------------------------------------------------
# COMPLEXITY (R rows, C columns)
# ---------------------------------------------------------------
#
#   Solution              | Time                | Extra space
#   ----------------------|---------------------|----------------------
#   1. DFS (recursive)    | O(R * C)            | O(R * C) copy + recursion
#   2. BFS                | O(R * C)            | O(R * C) seen set
#   3. Union-find         | about O(R * C)      | O(R * C) parent table
#   Flood fill            | O(R * C)            | O(R * C)
#   Max area              | O(R * C)            | O(R * C)
#
# Each cell is a node with at most 4 edges, so O(V + E) from
# graph_basics.py becomes O(R * C).


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

GRID_1 = [list("11110"), list("11010"), list("11000"), list("00000")]
GRID_2 = [list("11000"), list("11000"), list("00100"), list("00011")]


def run_tests():
    import random

    cases = [
        (GRID_1, 1),                                      # LeetCode example 1
        (GRID_2, 3),                                      # LeetCode example 2
        ([["0"]], 0),
        ([["1"]], 1),
        ([list("101"), list("010"), list("101")], 5),     # diagonals don't connect
        ([list("111"), list("101"), list("111")], 1),     # a ring is one island
    ]
    for solve in [num_islands_dfs, num_islands_bfs, num_islands_union_find]:
        for grid, expected in cases:
            original = [row[:] for row in grid]
            assert solve(grid) == expected, (solve.__name__, grid)
            assert grid == original, f"{solve.__name__} changed the input"

    # The three agree on random grids
    random.seed(10)
    for _ in range(200):
        rows, cols = random.randint(1, 8), random.randint(1, 8)
        grid = [[random.choice("01") for _ in range(cols)] for _ in range(rows)]
        answers = {num_islands_dfs(grid), num_islands_bfs(grid), num_islands_union_find(grid)}
        assert len(answers) == 1, grid

    # Flood fill (LeetCode 733 examples)
    assert flood_fill([[1, 1, 1], [1, 1, 0], [1, 0, 1]], 1, 1, 2) == \
        [[2, 2, 2], [2, 2, 0], [2, 0, 1]]
    assert flood_fill([[0, 0, 0], [0, 0, 0]], 0, 0, 0) == [[0, 0, 0], [0, 0, 0]]

    # Max area (LeetCode 695 example)
    grid = [
        [0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0],
        [0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0],
        [0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0],
    ]
    assert max_area_of_island(grid) == 6
    assert max_area_of_island([[0, 0, 0, 0, 0, 0, 0, 0]]) == 0

    print("All tests passed!")


if __name__ == "__main__":
    print("Grid:")
    for row in GRID_2:
        print("  " + " ".join(row))
    print(f"Islands: {num_islands_bfs(GRID_2)}")

    # Alerts per host per hour: rows are hours 00-07, columns are hosts
    hosts = ["web1", "web2", "app1", "app2", "db1", "db2", "hr1", "hr2"]
    alerts = [
        [0, 0, 0, 0, 0, 0, 2, 0],
        [0, 0, 0, 0, 0, 0, 0, 0],
        [9, 7, 0, 0, 0, 0, 0, 0],
        [0, 8, 6, 0, 0, 0, 0, 0],
        [0, 0, 7, 9, 0, 0, 0, 0],
        [0, 0, 0, 8, 7, 0, 0, 3],
        [0, 0, 0, 0, 9, 8, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0],
    ]
    region = largest_region(alerts, is_hot=lambda v: v >= 5)
    print("\nAlerts per hour (rows) and host (columns), '#' = 5 or more:")
    print("        " + " ".join(f"{h:>4}" for h in hosts))
    for hour, row in enumerate(alerts):
        cells = " ".join(f"{'#' if (hour, c) in region else ('.' if v < 5 else '+'):>4}"
                         for c, v in enumerate(row))
        print(f"  {hour:02d}:00 {cells}")
    affected = sorted({hosts[c] for _, c in region}, key=hosts.index)
    hours = sorted({r for r, _ in region})
    print(f"Largest connected hot region: {len(region)} cells, "
          f"{hours[0]:02d}:00-{hours[-1]:02d}:00, hosts {affected}")
    print("A staircase like this suggests one attack moving host to host over time.")

    print()
    run_tests()
