# Attack Paths: what can an attacker reach, and how fast?
#
# A network is a graph: machines are nodes, and "A can log in to B" is an
# edge. Attackers think in these graphs. Once they land on one machine
# (a phished laptop, a public web server), they ask: what can I reach
# from here, and what's the shortest way to the crown jewels (the
# database, the domain controller)?
#
# Defenders should ask the same questions FIRST. This is exactly what
# BloodHound does for Active Directory: map who can reach what, and find
# the short paths nobody meant to leave open. This project builds a tiny
# version, using the BFS and shortest-path ideas from
# problem_solving/graph_basics.py and shortest_path.py.
#
# Topics covered here:
#   1. A network as a graph (who can reach whom)
#   2. Reachability: everything an attacker can get to (BFS/DFS)
#   3. The shortest attack path (fewest hops, BFS)
#   4. "Blast radius": how much each entry point exposes
#   5. Choke points: the one edge whose removal helps most
#   6. The tool: load a network from JSON, ask these questions
#   7. Practice, with tests
#
# HOW TO RUN IT
#   python3 main.py                            the lesson and the tests
#   python3 main.py --network net.json reach --from laptop
#   python3 main.py --network net.json path --from internet --to db
#   python3 main.py --network net.json blast
#
# Edges are DIRECTED: "A -> B" means from A you can reach B, not the
# other way. Access usually isn't symmetric.


import argparse
import json
import sys
from collections import deque


# ---------------------------------------------------------------
# 1. A network as a graph
# ---------------------------------------------------------------
#
# A dict maps each machine to the machines it can reach directly. This
# is an ADJACENCY LIST. A missing or empty list means a dead end (you
# can land there, but go nowhere from it).

EXAMPLE = {
    "internet": ["web"],                       # the attacker starts on the public web server
    "web": ["app"],                            # the web server can talk to the app server
    "app": ["db", "fileserver"],               # the app reaches the database and a file share
    "fileserver": ["backup"],
    "db": [],                                  # the crown jewels: a dead end
    "backup": ["db"],                          # but backups can reach the db too (a side door)
    "laptop": ["web", "fileserver"],           # a phished employee laptop
}


def neighbours(graph, node):
    return graph.get(node, [])


# ---------------------------------------------------------------
# 2. Reachability: everything reachable from a start
# ---------------------------------------------------------------
#
# From the compromised machine, which machines can the attacker
# eventually get to? Explore outward, keeping a set of everything seen
# so we never visit a node twice (networks have loops: backup -> db, and
# maybe db -> backup). This is breadth-first search; depth-first would
# give the same SET, just in a different order.

def reachable(graph, start):
    seen = {start}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for nxt in neighbours(graph, node):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen - {start}                      # everything reachable, not counting where we started


# ---------------------------------------------------------------
# 3. The shortest attack path (fewest hops)
# ---------------------------------------------------------------
#
# How few logins does it take to get from `start` to `goal`? BFS finds
# the fewest-hops path, because it explores in rings: all 1-hop machines,
# then 2-hop, and so on, so the first time it reaches the goal is by a
# shortest route. We remember each node's PARENT so we can rebuild the
# path afterwards. Returns None if the goal can't be reached at all.

def shortest_path(graph, start, goal):
    if start == goal:
        return [start]
    parent = {start: None}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for nxt in neighbours(graph, node):
            if nxt not in parent:
                parent[nxt] = node
                if nxt == goal:
                    return _rebuild(parent, goal)
                queue.append(nxt)
    return None


def _rebuild(parent, goal):
    path = []
    node = goal
    while node is not None:
        path.append(node)
        node = parent[node]
    return path[::-1]


# ---------------------------------------------------------------
# 4. Blast radius
# ---------------------------------------------------------------
#
# If this machine is compromised, how much of the network falls? That's
# just how many machines are reachable from it. Ranking every machine by
# its blast radius shows which ones matter most: the laptop that can
# reach everything is a bigger risk than one tucked in a corner. A
# defender hardens, monitors and isolates the high-blast machines first.

def blast_radius(graph):
    return {node: len(reachable(graph, node)) for node in graph}


def ranked_blast(graph):
    return sorted(blast_radius(graph).items(), key=lambda kv: (-kv[1], kv[0]))


# ---------------------------------------------------------------
# 5. Choke points
# ---------------------------------------------------------------
#
# Which single link, if cut, best protects the goal? Try removing each
# edge on the current shortest path and see what the new distance
# becomes (longer, or unreachable). Cutting an edge OFF the shortest
# path changes nothing, so only the path's edges are worth trying. This
# is a small version of what defenders do: find the one firewall rule or
# revoked permission that does the most good.

def path_length(graph, start, goal):
    path = shortest_path(graph, start, goal)
    return len(path) - 1 if path else None            # hops = nodes - 1; None if unreachable


def without_edge(graph, a, b):
    return {node: [n for n in nbrs if not (node == a and n == b)] for node, nbrs in graph.items()}


def best_edge_to_cut(graph, start, goal):
    path = shortest_path(graph, start, goal)
    if not path or len(path) < 2:
        return None
    base = len(path) - 1
    best = None
    for a, b in zip(path, path[1:]):
        new_len = path_length(without_edge(graph, a, b), start, goal)
        gain = float("inf") if new_len is None else new_len - base
        # On ties (e.g. a straight chain, where cutting any edge severs the
        # goal), prefer the edge CLOSEST to the goal: cutting there protects
        # it from every entry point, not just this path's. ">=" keeps the
        # last such edge, because the path runs start -> goal.
        if best is None or gain >= best[0]:
            best = (gain, (a, b), new_len)
    gain, edge, new_len = best
    return {"cut": edge, "new_hops": new_len, "now_unreachable": new_len is None}


# ---------------------------------------------------------------
# 6. The tool
# ---------------------------------------------------------------

def load_network(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not all(isinstance(v, list) for v in data.values()):
        raise ValueError("a network must be a JSON object of {machine: [reachable machines]}")
    return data


def main(argv=None, out=sys.stdout):
    p = argparse.ArgumentParser(prog="main.py", description="Find what an attacker can reach in a network.")
    p.add_argument("--network", help="a JSON file of {machine: [reachable machines]} (default: the example)")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("reach"); r.add_argument("--from", dest="start", required=True)
    pa = sub.add_parser("path"); pa.add_argument("--from", dest="start", required=True)
    pa.add_argument("--to", dest="goal", required=True)
    sub.add_parser("blast")
    cut = sub.add_parser("cut"); cut.add_argument("--from", dest="start", required=True)
    cut.add_argument("--to", dest="goal", required=True)
    args = p.parse_args(argv)

    try:
        graph = load_network(args.network) if args.network else EXAMPLE
    except (OSError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    if args.command == "reach":
        got = reachable(graph, args.start)
        print(f"{args.start} can reach {len(got)}: {', '.join(sorted(got)) or '(nothing)'}", file=out)
    elif args.command == "path":
        path = shortest_path(graph, args.start, args.goal)
        if path is None:
            print(f"{args.goal} is not reachable from {args.start}", file=out)
            return 1
        print(f"{len(path) - 1} hops: {' -> '.join(path)}", file=out)
    elif args.command == "blast":
        for node, size in ranked_blast(graph):
            print(f"  {node:<14} reaches {size}", file=out)
    else:
        result = best_edge_to_cut(graph, args.start, args.goal)
        if result is None:
            print(f"no path from {args.start} to {args.goal} to cut", file=out)
            return 1
        a, b = result["cut"]
        if result["now_unreachable"]:
            print(f"cut {a} -> {b}: {args.goal} becomes unreachable", file=out)
        else:
            print(f"cut {a} -> {b}: shortest path grows to {result['new_hops']} hops", file=out)
    return 0


# ---------------------------------------------------------------
# The lesson
# ---------------------------------------------------------------

def lesson():
    print("  The network (-> means 'can log in to'):")
    for node, nbrs in EXAMPLE.items():
        print(f"    {node:<12} -> {', '.join(nbrs) or '(nothing)'}")

    print("\n  2. From the phished laptop, the attacker can reach:")
    print(f"       {', '.join(sorted(reachable(EXAMPLE, 'laptop')))}")

    print("\n  3. Shortest path from the internet to the database:")
    path = shortest_path(EXAMPLE, "internet", "db")
    print(f"       {len(path) - 1} hops: {' -> '.join(path)}")

    print("\n  4. Blast radius (compromise this, lose this many machines):")
    for node, size in ranked_blast(EXAMPLE)[:4]:
        print(f"       {node:<12} reaches {size}")

    print("\n  5. The best single link to cut on internet -> db:")
    result = best_edge_to_cut(EXAMPLE, "internet", "db")
    a, b = result["cut"]
    outcome = "db becomes unreachable" if result["now_unreachable"] else f"grows to {result['new_hops']} hops"
    print(f"       cut {a} -> {b}: {outcome}")


# ---------------------------------------------------------------
# 7. Practice and tests
# ---------------------------------------------------------------
#
# Practice: write choke_points(graph, start, goal): the machines (other
# than start and goal) that EVERY path from start to goal must pass
# through. Removing such a machine cuts the goal off entirely. (Hint:
# a node is a choke point if deleting it makes the goal unreachable.)
# Solution below.

def without_node(graph, node):
    return {n: [m for m in nbrs if m != node] for n, nbrs in graph.items() if n != node}


def choke_points(graph, start, goal):
    if shortest_path(graph, start, goal) is None:
        return []
    found = []
    for node in graph:
        if node in (start, goal):
            continue
        if shortest_path(without_node(graph, node), start, goal) is None:
            found.append(node)
    return sorted(found)


def run_tests():
    g = EXAMPLE

    # 2. Reachability, including through loops (backup <-> db)
    assert reachable(g, "laptop") == {"web", "app", "db", "fileserver", "backup"}
    assert reachable(g, "db") == set()                 # a dead end
    assert reachable(g, "backup") == {"db"}

    # 3. Shortest path, fewest hops
    assert shortest_path(g, "internet", "db") == ["internet", "web", "app", "db"]
    assert shortest_path(g, "db", "web") is None        # can't get there
    assert shortest_path(g, "web", "web") == ["web"]    # already there: 0 hops
    assert path_length(g, "internet", "db") == 3

    # A shorter route via a different start
    assert shortest_path(g, "laptop", "db") == ["laptop", "web", "app", "db"]

    # 4. Blast radius ranks the laptop and internet near the top
    blast = dict(blast_radius(g))
    assert blast["laptop"] == 5 and blast["db"] == 0
    assert ranked_blast(g)[0][0] in ("internet", "laptop")

    # 5. The naive cut (app -> db) does NOT help: backup -> db is a side
    #    door, so db stays reachable. The real choke from the internet is
    #    web -> app, and cutting it severs db.
    assert path_length(without_edge(g, "app", "db"), "internet", "db") == 5   # longer, via backup
    result = best_edge_to_cut(g, "internet", "db")
    assert result["cut"] == ("web", "app") and result["now_unreachable"]
    # On a graph with a detour, cutting lengthens the path instead of severing it
    detour = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    r = best_edge_to_cut(detour, "a", "d")
    assert r["new_hops"] == 2 and not r["now_unreachable"]    # a->b->d becomes a->c->d

    # The command line
    import io
    out = io.StringIO()
    assert main(["path", "--from", "internet", "--to", "db"], out=out) == 0
    assert "3 hops: internet -> web -> app -> db" in out.getvalue()
    out = io.StringIO()
    assert main(["path", "--from", "db", "--to", "web"], out=out) == 1 and "not reachable" in out.getvalue()
    out = io.StringIO()
    assert main(["reach", "--from", "laptop"], out=out) == 0 and "reach 5" in out.getvalue()

    # Loading a network from JSON, and rejecting junk
    import tempfile, os
    path = os.path.join(tempfile.mkdtemp(), "net.json")
    with open(path, "w") as f:
        json.dump({"a": ["b"], "b": []}, f)
    assert load_network(path) == {"a": ["b"], "b": []}
    bad = os.path.join(tempfile.mkdtemp(), "bad.json")
    with open(bad, "w") as f:
        f.write('{"a": "not a list"}')
    try:
        load_network(bad)
    except ValueError:
        pass
    else:
        raise AssertionError("a malformed network should be rejected")

    # Practice: choke points every path must cross
    assert choke_points(g, "internet", "db") == ["app", "web"]
    assert choke_points(detour, "a", "d") == []         # two independent routes: no single choke

    print("All tests passed!")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("--- Where can an attacker go, and how do we stop them? ---")
        lesson()
        print()
        run_tests()
    else:
        sys.exit(main())
