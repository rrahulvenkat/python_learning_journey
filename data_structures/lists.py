# Lists
#
# A list is an ORDERED, CHANGEABLE collection that allows DUPLICATES.
# Lists are written with square brackets: [1, 2, 3]
# They can hold any type, even a mix of types or other lists.
#
# Use a list when you have a sequence of items whose order matters
# and that you may need to add to, remove from, or change.
#
# Topics covered here:
#   1. Creating lists
#   2. Indexing and slicing
#   3. Changing items
#   4. Adding items: append, insert, extend
#   5. Removing items: remove, pop, del, clear
#   6. Searching: in, index, count
#   7. Sorting and reversing
#   8. Useful built-in functions: len, sum, min, max, any, all
#   9. Looping over lists
#  10. List comprehensions
#  11. Copying lists (and the "shared list" trap)
#  12. Nested lists (2D lists / matrices)
#  13. Unpacking
#  14. Lists as stacks and queues
#  15. Practical examples
#  16. Time complexity cheat sheet


from collections import deque


# ---------------------------------------------------------------
# 1. Creating lists
# ---------------------------------------------------------------

print("--- 1. Creating lists ---")

numbers = [10, 20, 30, 40, 50]
fruits = ["apple", "banana", "cherry"]
mixed = [1, "two", 3.0, True, None]
nested = [[1, 2], [3, 4]]
empty = []

from_string = list("abc")             # ['a', 'b', 'c']
from_range = list(range(1, 6))        # [1, 2, 3, 4, 5]
repeated = [0] * 5                    # [0, 0, 0, 0, 0]

print(numbers)
print(fruits)
print(mixed)
print(nested)
print(empty, len(empty))
print(from_string, from_range, repeated)


# ---------------------------------------------------------------
# 2. Indexing and slicing (same rules as strings)
# ---------------------------------------------------------------
#
#   List:      10  20  30  40  50
#   Index:      0   1   2   3   4
#   Negative:  -5  -4  -3  -2  -1

print("\n--- 2. Indexing and slicing ---")

print("numbers[0] =", numbers[0])
print("numbers[-1] =", numbers[-1])
print("numbers[1:4] =", numbers[1:4])     # index 1 to 3
print("numbers[:3] =", numbers[:3])       # first 3
print("numbers[-2:] =", numbers[-2:])     # last 2
print("numbers[::2] =", numbers[::2])     # every 2nd item
print("numbers[::-1] =", numbers[::-1])   # reversed copy
print("nested[1][0] =", nested[1][0])     # row 1, item 0 -> 3
# numbers[10] would raise IndexError


# ---------------------------------------------------------------
# 3. Changing items (lists are MUTABLE)
# ---------------------------------------------------------------

print("\n--- 3. Changing items ---")

colors = ["red", "green", "blue"]
colors[1] = "yellow"                  # change one item
print(colors)

colors[0:2] = ["black", "white"]      # change a slice
print(colors)

colors[1:2] = ["pink", "purple"]      # a slice can grow the list
print(colors)


# ---------------------------------------------------------------
# 4. Adding items
# ---------------------------------------------------------------

print("\n--- 4. Adding items ---")

tasks = ["study"]

tasks.append("exercise")              # add ONE item to the end
print("append:", tasks)

tasks.insert(0, "wake up")            # add at a position
print("insert:", tasks)

tasks.extend(["cook", "read"])        # add EACH item from another list
print("extend:", tasks)

tasks = tasks + ["sleep"]             # + makes a new combined list
print("+:     ", tasks)

# append vs extend
a = [1, 2]
a.append([3, 4])                      # adds the list as ONE item
print("append([3, 4]):", a)
b = [1, 2]
b.extend([3, 4])                      # adds 3 and 4 separately
print("extend([3, 4]):", b)


# ---------------------------------------------------------------
# 5. Removing items
# ---------------------------------------------------------------

print("\n--- 5. Removing items ---")

pets = ["cat", "dog", "fish", "dog", "bird"]

pets.remove("dog")                    # removes the FIRST match only
print("remove('dog'):", pets)

last = pets.pop()                     # removes and RETURNS the last item
print("pop():", pets, "| popped:", last)

first = pets.pop(0)                   # pop by index
print("pop(0):", pets, "| popped:", first)

del pets[0]                           # delete by index (returns nothing)
print("del pets[0]:", pets)

pets.clear()                          # empty the list
print("clear():", pets)

# remove() raises ValueError if the item isn't there, so check first
pets = ["cat"]
if "hamster" in pets:
    pets.remove("hamster")
else:
    print("No hamster to remove.")


# ---------------------------------------------------------------
# 6. Searching
# ---------------------------------------------------------------

print("\n--- 6. Searching ---")

scores = [72, 85, 90, 85, 64]

print("85 in scores:", 85 in scores)
print("100 not in scores:", 100 not in scores)
print("scores.index(85):", scores.index(85))     # first position
print("scores.count(85):", scores.count(85))     # how many times
# scores.index(100) raises ValueError


# ---------------------------------------------------------------
# 7. Sorting and reversing
# ---------------------------------------------------------------
#
# list.sort()   changes the list IN PLACE and returns None
# sorted(list)  returns a NEW sorted list, the original is unchanged

print("\n--- 7. Sorting ---")

values = [5, 2, 9, 1, 7]

new_list = sorted(values)
print("sorted(values):", new_list, "| original:", values)

values.sort()
print("values.sort():", values)

values.sort(reverse=True)
print("reverse=True: ", values)

values.reverse()                      # reverse the current order
print("reverse():    ", values)

# Common mistake: sort() returns None
result = [3, 1, 2].sort()
print("x = list.sort() gives:", result)

# Sorting with a key
words = ["banana", "Kiwi", "apple", "fig"]
print("by length:", sorted(words, key=len))
print("ignoring case:", sorted(words, key=str.lower))

students = [("Asha", 88), ("Ben", 72), ("Chen", 95)]
print("by score (high first):", sorted(students, key=lambda s: s[1], reverse=True))


# ---------------------------------------------------------------
# 8. Useful built-in functions
# ---------------------------------------------------------------

print("\n--- 8. Built-in functions ---")

marks = [72, 85, 90, 64, 88]

print("len:", len(marks))
print("sum:", sum(marks))
print("min:", min(marks), "| max:", max(marks))
print("average:", sum(marks) / len(marks))
print("any > 89:", any(m > 89 for m in marks))   # at least one True?
print("all > 60:", all(m > 60 for m in marks))   # every one True?


# ---------------------------------------------------------------
# 9. Looping over lists
# ---------------------------------------------------------------

print("\n--- 9. Looping ---")

for fruit in fruits:
    print("Fruit:", fruit)

for i, fruit in enumerate(fruits, start=1):
    print(f"{i}. {fruit}")

prices = [40, 25, 60]
for fruit, price in zip(fruits, prices):
    print(f"{fruit}: Rs. {price}")

# Don't remove items from a list while looping over it.
# Build a new list instead (see comprehensions below).


# ---------------------------------------------------------------
# 10. List comprehensions
# ---------------------------------------------------------------
#
#   [expression for item in iterable]
#   [expression for item in iterable if condition]
#   [a if condition else b for item in iterable]

print("\n--- 10. Comprehensions ---")

squares = [n ** 2 for n in range(1, 6)]
print("squares:", squares)

evens = [n for n in range(1, 11) if n % 2 == 0]
print("evens:", evens)

labels = ["even" if n % 2 == 0 else "odd" for n in range(1, 6)]
print("labels:", labels)

lengths = [len(f) for f in fruits]
print("lengths:", lengths)

passed = [m for m in marks if m >= 75]
print("passed:", passed)


# ---------------------------------------------------------------
# 11. Copying lists
# ---------------------------------------------------------------
#
# "=" does NOT copy a list. Both names point to the SAME list.

print("\n--- 11. Copying ---")

original = [1, 2, 3]
same = original                       # not a copy!
same.append(4)
print("original after changing 'same':", original)

copy1 = original.copy()               # three ways to make a real copy
copy2 = original[:]
copy3 = list(original)
copy1.append(99)
print("original after changing copy1:", original)

# Shallow vs deep copy: with nested lists, .copy() only copies the
# outer list. The inner lists are still shared.
import copy

grid = [[1, 2], [3, 4]]
shallow = grid.copy()
deep = copy.deepcopy(grid)
shallow[0][0] = "X"
print("grid after changing shallow[0][0]:", grid)    # changed!
deep[1][1] = "Y"
print("grid after changing deep[1][1]:  ", grid)     # unchanged


# ---------------------------------------------------------------
# 12. Nested lists (2D lists)
# ---------------------------------------------------------------

print("\n--- 12. Nested lists ---")

matrix = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9],
]

print("matrix[1][2] =", matrix[1][2])     # row 1, column 2 -> 6

for row in matrix:
    print(" ".join(str(n) for n in row))

column_0 = [row[0] for row in matrix]
print("first column:", column_0)

flat = [n for row in matrix for n in row]
print("flattened:", flat)

transposed = [list(col) for col in zip(*matrix)]
print("transposed:", transposed)

# Trap: [[0] * 3] * 3 makes 3 references to the SAME inner list
bad = [[0] * 3] * 3
bad[0][0] = 1
print("bad grid:", bad)
good = [[0] * 3 for _ in range(3)]
good[0][0] = 1
print("good grid:", good)


# ---------------------------------------------------------------
# 13. Unpacking
# ---------------------------------------------------------------

print("\n--- 13. Unpacking ---")

point = [3, 7]
x, y = point
print(f"x={x}, y={y}")

first, *middle, last = [1, 2, 3, 4, 5]
print(f"first={first}, middle={middle}, last={last}")

print(*fruits)                        # * spreads items into separate arguments


# ---------------------------------------------------------------
# 14. Lists as stacks and queues
# ---------------------------------------------------------------

print("\n--- 14. Stack and queue ---")

# Stack: Last In, First Out (like a pile of plates)
stack = []
stack.append("page1")
stack.append("page2")
stack.append("page3")
print("stack:", stack)
print("pop ->", stack.pop(), "| stack:", stack)

# Queue: First In, First Out (like a line at a shop).
# list.pop(0) is slow for big lists, so use collections.deque.
queue = deque(["Asha", "Ben"])
queue.append("Chen")                  # join the back
print("queue:", list(queue))
print("popleft ->", queue.popleft(), "| queue:", list(queue))


# ---------------------------------------------------------------
# 15. Practical examples
# ---------------------------------------------------------------

print("\n--- 15. Practical examples ---")

# Remove duplicates while keeping the original order
emails = ["a@x.com", "b@x.com", "a@x.com", "c@x.com", "b@x.com"]
unique = []
for e in emails:
    if e not in unique:
        unique.append(e)
print("unique emails:", unique)

# Find the second largest number
nums = [12, 45, 7, 45, 33]
distinct = sorted(set(nums), reverse=True)
print("second largest:", distinct[1])

# Split a list into chunks of 3
items = list(range(1, 11))
chunks = [items[i:i + 3] for i in range(0, len(items), 3)]
print("chunks:", chunks)

# Running total
running = []
total = 0
for n in [5, 10, 15, 20]:
    total += n
    running.append(total)
print("running total:", running)


# ---------------------------------------------------------------
# 16. Time complexity cheat sheet (n = length of the list)
# ---------------------------------------------------------------
#
#   Operation                     | Speed
#   ------------------------------|---------------------------
#   lst[i], lst[i] = x            | O(1)   instant
#   lst.append(x), lst.pop()      | O(1)   instant
#   lst.insert(0, x), lst.pop(0)  | O(n)   shifts every item
#   x in lst, lst.index(x)        | O(n)   checks items one by one
#   lst.remove(x)                 | O(n)
#   lst.sort(), sorted(lst)       | O(n log n)
#
# If you check "x in collection" a lot, a set is much faster (O(1)).
