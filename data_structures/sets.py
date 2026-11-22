# Sets
#
# A set is an UNORDERED collection of UNIQUE items.
#
#   - Written with curly braces: {1, 2, 3}
#   - Duplicates are removed automatically
#   - No order, so no indexing: my_set[0] doesn't work
#   - Items must be immutable (numbers, strings, tuples)
#   - The set itself is changeable (use frozenset for a fixed one)
#   - Checking "x in my_set" is very fast, even for huge sets
#
# Use a set when you care about WHETHER something is present, not
# about order or how many times it appears.
#
# Topics covered here:
#   1. Creating sets
#   2. Removing duplicates
#   3. Adding items
#   4. Removing items
#   5. Membership testing (and why sets are fast)
#   6. Set operations: union, intersection, difference, symmetric difference
#   7. Comparing sets: subset, superset, disjoint
#   8. Updating a set in place
#   9. Looping and set comprehensions
#  10. frozenset
#  11. Practical examples
#  12. Time complexity cheat sheet


import time


# ---------------------------------------------------------------
# 1. Creating sets
# ---------------------------------------------------------------

print("--- 1. Creating sets ---")

colors = {"red", "green", "blue"}
numbers = {3, 1, 4, 1, 5, 9, 2, 6, 5}     # duplicates are dropped
mixed = {1, "two", 3.0, (4, 5)}           # tuples are allowed
from_list = set([1, 2, 2, 3])
from_string = set("hello")                # unique characters

empty_set = set()                         # {} would make a DICTIONARY
empty_dict = {}

print(colors)
print(numbers)                            # order is not guaranteed
print(mixed)
print(from_list, from_string)
print("set():", type(empty_set).__name__, "| {}:", type(empty_dict).__name__)

# {[1, 2]} would raise TypeError: unhashable type: 'list'


# ---------------------------------------------------------------
# 2. Removing duplicates
# ---------------------------------------------------------------

print("\n--- 2. Removing duplicates ---")

visitors = ["asha", "ben", "asha", "chen", "ben", "asha"]
unique_visitors = set(visitors)
print("unique visitors:", unique_visitors)
print("how many unique:", len(unique_visitors))

# Back to a sorted list
print("sorted list:", sorted(unique_visitors))

# set() loses the original order. To keep it, use dict.fromkeys()
print("in original order:", list(dict.fromkeys(visitors)))


# ---------------------------------------------------------------
# 3. Adding items
# ---------------------------------------------------------------

print("\n--- 3. Adding ---")

tags = {"python"}
tags.add("security")                      # add one item
tags.add("python")                        # already there, nothing happens
print("add():", tags)

tags.update(["ai", "linux"], {"git"})     # add many items from iterables
print("update():", tags)


# ---------------------------------------------------------------
# 4. Removing items
# ---------------------------------------------------------------

print("\n--- 4. Removing ---")

langs = {"python", "java", "c", "rust", "go"}

langs.remove("java")                      # KeyError if missing
print("remove('java'):", langs)

langs.discard("php")                      # no error if missing
print("discard('php'):", langs)

try:
    langs.remove("php")
except KeyError as error:
    print("remove('php') -> KeyError:", error)

item = langs.pop()                        # removes a RANDOM item
print("pop() removed:", item)

langs.clear()
print("clear():", langs)


# ---------------------------------------------------------------
# 5. Membership testing
# ---------------------------------------------------------------
#
# Sets use hashing, so "in" takes about the same time no matter how
# big the set is. A list has to check items one by one.

print("\n--- 5. Membership ---")

allowed = {"rahul", "asha", "admin"}
print("'rahul' in allowed:", "rahul" in allowed)
print("'guest' not in allowed:", "guest" not in allowed)

big_list = list(range(1_000_000))
big_set = set(big_list)

start = time.perf_counter()
for _ in range(100):
    999_999 in big_list
list_time = time.perf_counter() - start

start = time.perf_counter()
for _ in range(100):
    999_999 in big_set
set_time = time.perf_counter() - start

print(f"100 lookups in a list: {list_time:.4f} s")
print(f"100 lookups in a set:  {set_time:.6f} s")


# ---------------------------------------------------------------
# 6. Set operations
# ---------------------------------------------------------------
#
#   Operation             | Operator | Method                    | Meaning
#   ----------------------|----------|---------------------------|------------------------
#   Union                 | a | b    | a.union(b)                | in a OR b (everything)
#   Intersection          | a & b    | a.intersection(b)         | in BOTH a and b
#   Difference            | a - b    | a.difference(b)           | in a but NOT in b
#   Symmetric difference  | a ^ b    | a.symmetric_difference(b) | in one but NOT both

print("\n--- 6. Set operations ---")

python_club = {"asha", "ben", "chen", "dev"}
security_club = {"chen", "dev", "eli", "fay"}

print("python club:  ", sorted(python_club))
print("security club:", sorted(security_club))
print("union (|):          ", sorted(python_club | security_club))
print("intersection (&):   ", sorted(python_club & security_club))
print("difference (-):     ", sorted(python_club - security_club))
print("difference reversed:", sorted(security_club - python_club))
print("symmetric diff (^): ", sorted(python_club ^ security_club))

# Methods accept any iterable, operators need sets on both sides
print("union with a list:", sorted(python_club.union(["zoe"])))

# Works with more than two sets too
c = {"chen", "zoe"}
print("in all three:", python_club & security_club & c)


# ---------------------------------------------------------------
# 7. Comparing sets
# ---------------------------------------------------------------

print("\n--- 7. Comparing sets ---")

all_perms = {"read", "write", "delete", "admin"}
user_perms = {"read", "write"}
guest_perms = {"read"}
other = {"print"}

print("user <= all (subset):", user_perms <= all_perms)
print("user.issubset(all):", user_perms.issubset(all_perms))
print("all >= user (superset):", all_perms >= user_perms)
print("guest < user (proper subset):", guest_perms < user_perms)
print("user.isdisjoint(other):", user_perms.isdisjoint(other))   # nothing in common
print("{1, 2} == {2, 1}:", {1, 2} == {2, 1})                     # order doesn't matter


# ---------------------------------------------------------------
# 8. Updating a set in place
# ---------------------------------------------------------------
#
# The operators above make NEW sets. These change the set itself.

print("\n--- 8. In-place updates ---")

s = {1, 2, 3, 4}
s |= {5, 6}                               # same as s.update({5, 6})
print("|= ", s)
s &= {2, 3, 4, 5, 10}                     # keep only common items
print("&= ", s)
s -= {2}                                  # remove these items
print("-= ", s)
s ^= {5, 7}                               # toggle these items
print("^= ", s)


# ---------------------------------------------------------------
# 9. Looping and set comprehensions
# ---------------------------------------------------------------

print("\n--- 9. Looping and comprehensions ---")

for color in sorted(colors):              # sort for a predictable order
    print(" ", color)

squares = {n ** 2 for n in range(-3, 4)}  # duplicates removed: 9, 4, 1, 0
print("squares:", sorted(squares))

sentence = "the quick brown fox jumps over the lazy dog"
first_letters = {w[0] for w in sentence.split()}
print("first letters:", sorted(first_letters))


# ---------------------------------------------------------------
# 10. frozenset: an immutable set
# ---------------------------------------------------------------
#
# A frozenset can't be changed, so it can be a dictionary key or an
# item inside another set.

print("\n--- 10. frozenset ---")

weekend = frozenset({"Sat", "Sun"})
print(weekend)
print("'Sun' in weekend:", "Sun" in weekend)
# weekend.add("Fri") would raise AttributeError

team_projects = {
    frozenset({"asha", "ben"}): "Password Analyzer",
    frozenset({"chen", "dev"}): "Log Analyzer",
}
print("asha + ben work on:", team_projects[frozenset({"ben", "asha"})])


# ---------------------------------------------------------------
# 11. Practical examples
# ---------------------------------------------------------------

print("\n--- 11. Practical examples ---")

# Find common and different items between two lists
yesterday_ips = ["10.0.0.5", "10.0.0.8", "192.168.1.50"]
today_ips = ["10.0.0.5", "172.16.0.3", "192.168.1.50", "10.0.0.9"]
print("seen both days:", sorted(set(yesterday_ips) & set(today_ips)))
print("new today:     ", sorted(set(today_ips) - set(yesterday_ips)))

# Check for duplicates in a list
def has_duplicates(items):
    return len(items) != len(set(items))


print("has_duplicates([1, 2, 3]):", has_duplicates([1, 2, 3]))
print("has_duplicates([1, 2, 2]):", has_duplicates([1, 2, 2]))

# Check if a password uses enough different kinds of characters
import string

password = "S3cure!Pass"
chars = set(password)
kinds = {
    "lowercase": bool(chars & set(string.ascii_lowercase)),
    "uppercase": bool(chars & set(string.ascii_uppercase)),
    "digits": bool(chars & set(string.digits)),
    "symbols": bool(chars & set(string.punctuation)),
}
print(f"'{password}' uses:", [k for k, v in kinds.items() if v])

# Pangram: does a sentence use every letter of the alphabet?
alphabet = set(string.ascii_lowercase)
print("pangram?", alphabet <= set(sentence.lower()))

# Blocklist check
blocked = {"password", "123456", "qwerty", "letmein"}
for attempt in ["qwerty", "Tr1ckyOne!"]:
    status = "rejected (too common)" if attempt.lower() in blocked else "allowed"
    print(f"  {attempt:<12} {status}")


# ---------------------------------------------------------------
# 12. Time complexity cheat sheet
# ---------------------------------------------------------------
#
#   Operation                     | Speed
#   ------------------------------|---------------------------
#   x in s                        | O(1)   instant
#   s.add(x), s.remove(x)         | O(1)
#   a | b                         | O(len(a) + len(b))
#   a & b                         | O(min(len(a), len(b)))
#   a - b                         | O(len(a))
#
# Choosing a collection:
#   list       -> ordered, duplicates allowed, changeable
#   tuple      -> ordered, duplicates allowed, fixed
#   set        -> unordered, unique items, fast "in" checks
#   dict       -> key: value lookups
