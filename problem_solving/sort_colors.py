# Sort Colors (LeetCode 75)  -  counting sort and the Dutch national flag
#
# PROBLEM
# -------
# A list contains only 0s, 1s and 2s (red, white and blue). Sort it
# IN PLACE, without sort() or sorted().
#
#   [2, 0, 2, 1, 1, 0]  ->  [0, 0, 1, 1, 2, 2]
#
# Follow-up: do it in ONE pass using O(1) extra space.
#
# KEY IDEAS
# ---------
#   - When there are only a few possible values, you don't need to
#     COMPARE items at all. Count how many of each there are, then
#     write them back in order. That's counting sort: O(n), which
#     beats the O(n log n) limit in sorting_algorithms.py because it
#     uses what you know about the data.
#   - One pass: the DUTCH NATIONAL FLAG algorithm (by Edsger
#     Dijkstra) keeps three regions, using three pointers:
#
#       [ 0 0 0 | 1 1 1 | ? ? ? ? | 2 2 2 ]
#                 ^low    ^mid      ^high
#
#       everything before low       is 0
#       low up to (not incl.) mid   is 1
#       mid up to high              is not looked at yet
#       everything after high       is 2
#
# WHAT'S NEW HERE
# ---------------
# Three-way partitioning with pointers. The two-pointer technique in
# palindrome.py moved two pointers inwards; here three pointers grow
# three regions at once. Quicksort's partition step works the same way.
#
# SECURITY CONNECTION
# -------------------
# Alert triage sorts by a handful of severity levels. With only a few
# possible keys, bucketing (variation 2) groups thousands of alerts in
# one pass and keeps them in time order within each level.


# ---------------------------------------------------------------
# Solution 1: counting sort (two passes)
# ---------------------------------------------------------------
#
#   [2, 0, 2, 1, 1, 0]
#   pass 1, count:   0 -> 2,  1 -> 2,  2 -> 2
#   pass 2, write:   [0, 0, 1, 1, 2, 2]
#
# The list is changed in place (nums[i] = ...), and nothing is
# returned, which is what LeetCode asks for.

def sort_colors_counting(nums):
    counts = [0, 0, 0]
    for num in nums:
        counts[num] += 1

    i = 0
    for value in (0, 1, 2):
        for _ in range(counts[value]):
            nums[i] = value
            i += 1


# ---------------------------------------------------------------
# Solution 2: Dutch national flag (one pass, the optimal answer)
# ---------------------------------------------------------------
#
# Look at nums[mid]:
#   0 -> swap it with nums[low]; low and mid both move right
#   1 -> it's already in the right region; mid moves right
#   2 -> swap it with nums[high]; high moves LEFT. mid stays put,
#        because the item that just arrived from the right hasn't
#        been looked at yet.
# Stop when mid passes high.
#
# Trace for [2, 0, 2, 1, 1, 0]:
#
#   list                | low mid high | nums[mid] | action
#   --------------------|--------------|-----------|------------------
#   [2, 0, 2, 1, 1, 0]  |  0   0   5   |    2      | swap mid, high
#   [0, 0, 2, 1, 1, 2]  |  0   0   4   |    0      | swap low, mid
#   [0, 0, 2, 1, 1, 2]  |  1   1   4   |    0      | swap low, mid
#   [0, 0, 2, 1, 1, 2]  |  2   2   4   |    2      | swap mid, high
#   [0, 0, 1, 1, 2, 2]  |  2   2   3   |    1      | mid + 1
#   [0, 0, 1, 1, 2, 2]  |  2   3   3   |    1      | mid + 1
#   mid (4) > high (3): done

def sort_colors(nums):
    low, mid, high = 0, 0, len(nums) - 1
    while mid <= high:
        if nums[mid] == 0:
            nums[low], nums[mid] = nums[mid], nums[low]
            low += 1
            mid += 1
        elif nums[mid] == 1:
            mid += 1
        else:
            nums[mid], nums[high] = nums[high], nums[mid]
            high -= 1                             # don't move mid yet


# ---------------------------------------------------------------
# Variation 1: three-way partition around ANY pivot
# ---------------------------------------------------------------
#
# The same algorithm works for any list: put everything smaller than
# the pivot first, equal in the middle, larger last. This is how a
# fast in-place quicksort handles lots of repeated values.
#   partition([5, 1, 8, 5, 3, 9, 5], 5)  ->  [1, 3, 5, 5, 5, 9, 8]
#   (the order inside each group may vary)

def three_way_partition(nums, pivot):
    low, mid, high = 0, 0, len(nums) - 1
    while mid <= high:
        if nums[mid] < pivot:
            nums[low], nums[mid] = nums[mid], nums[low]
            low += 1
            mid += 1
        elif nums[mid] == pivot:
            mid += 1
        else:
            nums[mid], nums[high] = nums[high], nums[mid]
            high -= 1
    return low, high                              # where the "equal" group sits


# ---------------------------------------------------------------
# Variation 2: bucket alerts by severity (stable, one pass)
# ---------------------------------------------------------------
#
# Counting sort generalised: one bucket (list) per possible key. Each
# alert goes into its bucket in the order it arrives, so the result is
# STABLE: alerts keep their time order inside each severity.

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

def bucket_by_severity(alerts):
    buckets = {level: [] for level in SEVERITY_ORDER}
    for alert in alerts:
        buckets[alert["severity"]].append(alert)
    return [alert for level in SEVERITY_ORDER for alert in buckets[level]]


# ---------------------------------------------------------------
# COMPLEXITY (n = number of items, k = number of possible values)
# ---------------------------------------------------------------
#
#   Solution                   | Time      | Extra space | Passes
#   ---------------------------|-----------|-------------|-------
#   1. Counting sort           | O(n + k)  | O(k)        | 2
#   2. Dutch national flag     | O(n)      | O(1)        | 1
#   Three-way partition        | O(n)      | O(1)        | 1
#   Bucket by severity         | O(n + k)  | O(n)        | 1
#
# Counting sort is great when k is small (3 colours, 4 severities,
# 256 byte values). When k is huge, like any 64-bit number, the counts
# list would be enormous, so use a comparison sort instead.


# ---------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------

def run_tests():
    import random

    test_cases = [
        [2, 0, 2, 1, 1, 0],               # LeetCode example 1
        [2, 0, 1],                        # LeetCode example 2
        [],
        [0],
        [2, 2, 2],
        [1, 0],
        [2, 1, 0, 0, 1, 2],
    ]
    random.seed(4)
    test_cases += [[random.randint(0, 2) for _ in range(n)] for n in (10, 50, 1_000)]

    for solve in [sort_colors_counting, sort_colors]:
        for nums in test_cases:
            data = list(nums)
            returned = solve(data)                       # sorts in place
            assert returned is None
            assert data == sorted(nums), f"{solve.__name__} failed on {nums}"

    # Three-way partition: check the three groups, not exact order
    for nums, pivot in [([5, 1, 8, 5, 3, 9, 5], 5), ([3, 3, 3], 3), ([9, 1], 5), ([], 1)]:
        data = list(nums)
        low, high = three_way_partition(data, pivot)
        assert all(x < pivot for x in data[:low])
        assert all(x == pivot for x in data[low:high + 1])
        assert all(x > pivot for x in data[high + 1:])
        assert sorted(data) == sorted(nums)              # nothing lost

    # Buckets keep the original order within a severity
    alerts = [
        {"time": 1, "severity": "low", "msg": "a"},
        {"time": 2, "severity": "critical", "msg": "b"},
        {"time": 3, "severity": "low", "msg": "c"},
        {"time": 4, "severity": "high", "msg": "d"},
        {"time": 5, "severity": "critical", "msg": "e"},
    ]
    assert [a["msg"] for a in bucket_by_severity(alerts)] == ["b", "e", "d", "a", "c"]

    print("All tests passed!")


if __name__ == "__main__":
    nums = [2, 0, 2, 1, 1, 0]
    print(f"before: {nums}")
    sort_colors(nums)
    print(f"after:  {nums}")

    data = [5, 1, 8, 5, 3, 9, 5]
    low, high = three_way_partition(data, 5)
    print(f"\nPartition around 5: {data[:low]} | {data[low:high + 1]} | {data[high + 1:]}")

    alerts = [
        {"time": "09:01", "severity": "low", "msg": "port 80 scan from 198.51.100.7"},
        {"time": "09:03", "severity": "critical", "msg": "admin login from new country"},
        {"time": "09:04", "severity": "medium", "msg": "5 failed logins: bob"},
        {"time": "09:07", "severity": "critical", "msg": "outbound traffic to known C2"},
        {"time": "09:09", "severity": "high", "msg": "new service installed on web01"},
    ]
    print("\nAlert queue, most severe first (time order kept within each level):")
    for a in bucket_by_severity(alerts):
        print(f"  {a['severity']:<9} {a['time']}  {a['msg']}")

    print()
    run_tests()
